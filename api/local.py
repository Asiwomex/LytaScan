"""Loopback-only onboarding preview with fictional identities and AWS results."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock, Timer
from time import sleep
from uuid import uuid4

import boto3
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from moto import mock_aws
from pydantic import BaseModel, Field

from api.onboarding import get_organizations, get_setup_url, get_verifier, principal, router
from api.connection_cleanup import clean_now, get_cleanup_dispatcher
from api.org_jobs import get_dispatcher, router as jobs_router
from api.migration import router as migration_router
from api.lifecycle import router as lifecycle_router
from api.team import verified_email, router as team_router
from scanner.accounts import AccountStore, tenant_key
from scanner.coverage import assessment, UNAVAILABLE
from scanner.lifecycle import fingerprint
from scanner.check import Scope
from scanner.findings import Finding, format_timestamp
from scanner.org_jobs import JobConflict, OrgJobs, run_job
from scanner.organizations import OrganizationStore
from scanner.store import ScanStore
from scanner.registry import REGISTRY_VERSION
from scanner.scan_progress import job_checks

ORIGINS = [f"http://{host}:{port}" for host in ("127.0.0.1", "localhost") for port in (3000, 3100)]
LOCAL_ACCOUNT = "111122223333"
LOCK = Lock()
users: dict[str, dict] = {}
sessions: dict[str, tuple[str, datetime]] = {}

app = FastAPI(title="LytaScan local onboarding")
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["GET", "POST", "PATCH", "DELETE"],
                   allow_headers=["Authorization", "Content-Type"])


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _error: RequestValidationError):
    return JSONResponse({"detail": "Check your entries and try again."}, status_code=422)


@app.middleware("http")
async def local_only(request: Request, call_next):
    if request.url.hostname not in {"localhost", "127.0.0.1"} or request.headers.get("origin") not in (None, *ORIGINS):
        return JSONResponse({"detail": "This preview is available on localhost."}, status_code=403)
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    return response


# This entry point is never selected by the Lambda handler. Explicit fake
# credentials and Moto ensure these calls stay inside the local process.
mock = mock_aws()
mock.start()
table = boto3.resource("dynamodb", region_name="us-east-1", aws_access_key_id="local",
                       aws_secret_access_key="local").create_table(
    TableName="pillarscan-local-onboarding",
    KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
    AttributeDefinitions=[{"AttributeName": "PK", "AttributeType": "S"}, {"AttributeName": "SK", "AttributeType": "S"}],
    BillingMode="PAY_PER_REQUEST",
)
store = OrganizationStore(table)


def local_principal(request: Request) -> str:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    with LOCK:
        session = sessions.get(token)
    if scheme.lower() != "bearer" or not session or session[1] <= datetime.now(timezone.utc):
        raise HTTPException(401, "Sign in first.")
    return session[0]


def local_verifier(account: dict, _attempt: str) -> str:
    return "verified" if account["aws_account_id"] == LOCAL_ACCOUNT else "assume_denied"


def fixture_report(account, region, *, when=None):
    report = json.loads((Path(__file__).resolve().parents[1] / "sample-data" / "demo-findings.json").read_text(encoding="utf-8"))
    stamp = format_timestamp(when or datetime.now(timezone.utc))
    account_id = account["aws_account_id"]
    findings = []
    for finding in report["findings"]:
        if finding["region"] not in (region, "global"):
            continue
        finding["resource_arn"] = finding["resource_arn"].replace(finding["account_id"], account_id)
        findings.append({**finding, "account_id": account_id, "scanned_at": stamp})
    return {"scan": {**report["scan"], "account_id": account_id, "regions": [region],
                     "started_at": stamp, "finished_at": stamp}, "findings": findings}


def fixture_assessment(account, region, *, verification=None, progress=None, show_deletion=False):
    report = fixture_report(account, region)
    stamp = report["scan"]["started_at"]
    account_id = account["aws_account_id"]
    checks = job_checks(verification)
    examples = {
        "cloudwatch_alarm_actions": ("fail", f"arn:aws:cloudwatch:{region}:{account_id}:alarm:checkout-errors", "Configured actions are disabled."),
        "ec2_ebs_optimization": ("unknown", f"arn:aws:ec2:{region}:{account_id}:instance/i-00000000000000001", "The fixture has no EBS optimization capability data."),
        "s3_incomplete_multipart_cleanup": ("pass", "arn:aws:s3:::northwind-artifacts", "A bucket-wide abort rule is enabled."),
        "ec2_imdsv2_required": ("fail", f"arn:aws:ec2:{region}:{account_id}:instance/i-00000000000000002", "The sample instance allows IMDSv1."),
    }
    deletion_example = examples["ec2_imdsv2_required"][1]
    if show_deletion:
        del examples["ec2_imdsv2_required"]
    for check in checks:
        meta = check.meta
        if meta.check_id in examples:
            status, arn, description = examples[meta.check_id]
            report["findings"].append({
                "check_id": meta.check_id, "title": meta.title, "pillar": meta.pillar.value, "severity": meta.severity.value,
                "status": status, "resource_arn": arn, "resource_type": meta.resource_type,
                "region": "global" if meta.scope == Scope.GLOBAL else region, "account_id": account_id,
                "description": description, "remediation": meta.remediation, "scanned_at": stamp,
            })
    represented = set(report["scan"]["checks_run"]) | examples.keys() | {"ec2_imdsv2_required"}
    unavailable = {finding["check_id"] for finding in report["findings"] if finding["status"] in UNAVAILABLE}
    if verification and verification.get("finding_id"):
        report["findings"] = [
            {**finding, "status": "pass", "description": "The local verification fixture simulates a confirmed pass."}
            for finding in report["findings"] if fingerprint(
                account["organization_id"], account["account_connection_id"], finding
            ) == verification["finding_id"]
        ]
        unavailable = set()
    elif verification:
        selected = {check.meta.check_id for check in checks}
        report["findings"] = [finding for finding in report["findings"] if finding["check_id"] in selected]
    scopes = [
        {"check_id": check.meta.check_id, "pillar": check.meta.pillar.value,
         "region": "global" if check.meta.scope == Scope.GLOBAL else (verification or {}).get("region", region),
         "outcome": "incomplete" if check.meta.check_id in unavailable or check.meta.check_id not in represented else "complete"}
        for check in checks
    ]
    if progress:
        # Emit the same events as the worker, at a pace a local operator can inspect.
        counts = ("pass", "fail", "error", "unknown", "skipped", "not_applicable")
        for offset in range(0, len(scopes), 6):
            batch = scopes[offset:offset + 6]
            for scope in batch:
                progress({**scope, "status": "running"})
            sleep(0.25)
            for scope in batch:
                outcomes = [item["status"] for item in report["findings"] if item["check_id"] == scope["check_id"]]
                progress({
                    **scope, "status": scope["outcome"], "counts": {value: outcomes.count(value) for value in counts},
                    "reason_codes": ["fixture_data_unavailable"] if scope["outcome"] == "incomplete" else [],
                })
    report["scan"]["finished_at"] = format_timestamp(datetime.now(timezone.utc))
    report["scan"]["checks_run"] = [check.meta.check_id for check in checks]
    report["scan"]["assessment"] = {
        **assessment([Finding(**item) for item in report["findings"]], scopes),
        "registry_version": REGISTRY_VERSION, "scopes": scopes,
    }
    if not verification:
        report["inventory"] = [{
            "account_id": account_id, "resource_type": "AWS::EC2::Instance", "region": region,
            "complete": True, "resource_ids": [
                examples["ec2_ebs_optimization"][1], *([] if show_deletion else [deletion_example]),
            ],
        }]
    return report


def local_dispatch(org, job):
    def execute():
        jobs = OrgJobs(table)
        current = jobs.job(org, job)
        if not current:
            return
        previous = any(
            item["job_id"] != job and item["account_connection_id"] == current["account_connection_id"]
            and not item.get("verification") and item.get("track_findings")
            and item.get("findings_reconciled")
            for item in jobs.jobs(org)
        )

        def scan(account, region, *, verification=None, progress=None):
            return fixture_assessment(account, region, verification=verification, progress=progress, show_deletion=previous)

        try:
            run_job(jobs, org, job, scan, supports_progress=True)
        except JobConflict:
            # The first timer already owns this simulated job.
            return

    timer = Timer(1.5, execute)
    timer.daemon = True
    timer.start()


def local_verified_email(request: Request):
    subject = local_principal(request)
    with LOCK:
        email = next((email for email, user in users.items() if user["id"] == subject and "code" not in user), None)
    if not email:
        raise HTTPException(403, "Verify your email first.")
    return email


app.dependency_overrides.update({
    principal: local_principal,
    get_organizations: lambda: store,
    get_setup_url: lambda: lambda _: None,
    get_verifier: lambda: local_verifier,
    get_dispatcher: lambda: local_dispatch,
    get_cleanup_dispatcher: lambda: clean_now,
    verified_email: local_verified_email,
})
app.include_router(router)
app.include_router(team_router)
app.include_router(jobs_router)
app.include_router(migration_router)
app.include_router(lifecycle_router)


@app.post("/local/seed-legacy")
def seed_legacy(request: Request):
    actor = local_principal(request)
    AccountStore(table).connect(actor, LOCAL_ACCOUNT)
    report = fixture_report({"aws_account_id": LOCAL_ACCOUNT}, "us-east-1",
                            when=datetime.now(timezone.utc).replace(hour=12, minute=0, second=0, microsecond=0) - timedelta(days=1))
    return {"scan_id": ScanStore(table).put_scan(report, owner=tenant_key(actor, LOCAL_ACCOUNT))}


class Login(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)


class Confirm(BaseModel):
    email: str = Field(max_length=254)
    code: str = Field(pattern=r"^[0-9]{6}$")


def local_email(value: str) -> str:
    email = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9._+-]+@example\.test", email):
        raise HTTPException(422, "Use a fictional address ending in @example.test.")
    return email


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)


@app.post("/local/register", status_code=201)
def register(body: Login) -> dict[str, str]:
    email = local_email(body.email)
    salt = secrets.token_bytes(16)
    code = f"{secrets.randbelow(1_000_000):06d}"
    with LOCK:
        if email in users:
            raise HTTPException(409, "That fictional address is already registered.")
        users[email] = {"id": uuid4().hex, "salt": salt, "hash": password_hash(body.password, salt),
                        "code": code, "expires": datetime.now(timezone.utc) + timedelta(minutes=10)}
    return {"code": code}


@app.post("/local/confirm")
def confirm(body: Confirm) -> dict[str, bool]:
    email = local_email(body.email)
    with LOCK:
        user = users.get(email)
        if not user or not user.get("code") or user["expires"] <= datetime.now(timezone.utc) or not secrets.compare_digest(user["code"], body.code):
            raise HTTPException(422, "The local verification code is invalid or expired.")
        del user["code"]
    return {"confirmed": True}


@app.post("/local/sign-in")
def sign_in(body: Login) -> dict[str, str | int]:
    email = local_email(body.email)
    with LOCK:
        user = users.get(email)
        if not user or "code" in user or not secrets.compare_digest(user["hash"], password_hash(body.password, user["salt"])):
            raise HTTPException(401, "Check your local credentials and email verification.")
        token = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        sessions[token] = (user["id"], expires)
    return {"accessToken": token, "email": email, "expiresAt": int(expires.timestamp() * 1000)}


@app.post("/local/sign-out")
def sign_out(request: Request) -> dict[str, bool]:
    local_principal(request)
    token = request.headers["authorization"].partition(" ")[2]
    with LOCK:
        sessions.pop(token, None)
    return {"signed_out": True}

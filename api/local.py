"""Loopback-only onboarding preview with fictional identities and AWS results."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock, Timer
from uuid import uuid4

import boto3
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from moto import mock_aws
from pydantic import BaseModel, Field

from api.onboarding import get_organizations, get_setup_url, get_verifier, principal, router
from api.org_jobs import get_dispatcher, router as jobs_router
from api.migration import router as migration_router
from api.team import verified_email, router as team_router
from scanner.accounts import AccountStore, tenant_key
from scanner.findings import format_timestamp
from scanner.org_jobs import JobConflict, OrgJobs, run_job
from scanner.organizations import OrganizationStore
from scanner.store import ScanStore

ORIGINS = ["http://127.0.0.1:3000", "http://localhost:3000"]
LOCAL_ACCOUNT = "111122223333"
LOCK = Lock()
users: dict[str, dict] = {}
sessions: dict[str, tuple[str, datetime]] = {}

app = FastAPI(title="Pillarscan local onboarding")
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["GET", "POST"],
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


def local_dispatch(org, job):
    def execute():
        try:
            run_job(OrgJobs(table), org, job, fixture_report)
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
    verified_email: local_verified_email,
})
app.include_router(router)
app.include_router(team_router)
app.include_router(jobs_router)
app.include_router(migration_router)


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

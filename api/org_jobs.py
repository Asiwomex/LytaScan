"""Organization-scoped scan requests and results."""

import json
import os
import time
from collections.abc import Callable
from functools import lru_cache
from typing import Annotated, Literal
from uuid import UUID

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from botocore.config import Config
from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field, model_validator

from api.onboarding import AccountId, OrgId, Organizations, Principal
from scanner.org_jobs import ACTIVE, READ_ROLES, SCAN_ROLES, JobConflict, OrgJobs
from scanner.findings import Pillar
from scanner.scan_progress import job_plan, job_scope_summary, scope_snapshot, summarize_scopes
from scanner.store import ScanStore

router = APIRouter(prefix="/v1/orgs")
JobId = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]


class ScanRequest(BaseModel):
    request_id: UUID


class CreateScan(ScanRequest):
    mode: Literal["full", "quick", "pillar"] = "full"
    pillar: Pillar | None = None

    @model_validator(mode="after")
    def valid_mode(self):
        if (self.mode == "pillar") != (self.pillar is not None):
            raise ValueError("Choose a pillar only for a pillar scan.")
        return self


class RetryScope(ScanRequest):
    check_id: str = Field(pattern=r"^[a-z0-9_]{1,80}$")
    region: str = Field(pattern=r"^[a-z0-9-]{1,32}$")


def authorize(store, actor, org, roles=READ_ROLES):
    member = store.membership(actor, org)
    if member is None:
        raise HTTPException(404, "Organization not found.")
    if member["role"] not in roles:
        raise HTTPException(403, "Your organization role does not allow this action.")
    return member


def has_account(member, generation):
    return member["role"] in ("owner", "administrator") or member.get("allowed_account") == generation


@lru_cache
def get_dispatcher():
    def dispatch(org: str, job_id: str):
        boto3.client("sqs", config=Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 2})).send_message(
            QueueUrl=os.environ["SCAN_QUEUE_URL"],
            MessageBody=json.dumps({"operation": "org_scan", "organization_id": org, "job_id": job_id}),
        )
    return dispatch


Dispatch = Annotated[Callable[[str, str], None], Depends(get_dispatcher)]


def public_job(job, store=None):
    fields = ("job_id", "aws_account_id", "region", "state", "created_at",
              "started_at", "finished_at", "counts", "error_message", "source")
    result = {field: job.get(field) for field in fields}
    result["findings_reconciled"] = not job.get("track_findings") or bool(job.get("findings_reconciled"))
    result["reconciliation_expired"] = not result["findings_reconciled"] and job["deadline"] <= time.time()
    if result["reconciliation_expired"] and job["state"] == "complete":
        result["error_message"] = "Finding reconciliation did not finish before its deadline."
    selection = job.get("verification") or {}
    default_kind = "verification" if selection.get("finding_id") else "full"
    result["kind"] = selection.get("kind", default_kind)
    result["pillar"] = selection.get("pillar")
    result["scope_progress"] = job_scope_summary(store, job) if store is not None else job.get("scope_progress")
    if job["state"] in ACTIVE and job["deadline"] <= time.time():
        result.update(state="expired", error_message="The scan did not finish before its deadline.")
    return result


def scoped_job(store, org, job_id, member=None):
    job = store.job(org, job_id)
    if not job:
        raise HTTPException(404, "Scan job not found.")
    if job["expires_at"] <= time.time():
        raise HTTPException(404, "Scan job has expired.")
    connection = store.connection(org, job["aws_account_id"])
    if not connection or connection["account_connection_id"] != job["account_connection_id"]:
        raise HTTPException(404, "Scan job not found.")
    if member is not None and not has_account(member, job["account_connection_id"]):
        raise HTTPException(404, "Scan job not found.")
    return job


@router.get("/{org_id}/jobs")
def list_jobs(org_id: OrgId, actor: Principal, store: Organizations):
    member = authorize(store, actor, org_id)
    jobs = OrgJobs(store.table)
    connections = {item["account_connection_id"] for item in store.connections(org_id) if has_account(member, item["account_connection_id"])}
    visible = sorted(
        (job for job in jobs.jobs(org_id) if job["account_connection_id"] in connections and job["expires_at"] > time.time()),
        key=lambda job: (job["created_at"], job["job_id"]), reverse=True,
    )
    latest_success = {}
    for job in visible:
        if job["state"] == "complete" and not job.get("verification") and job.get("source") != "legacy":
            latest_success.setdefault(job["account_connection_id"], job["finished_at"])
    result = []
    for job in visible[:30]:
        row = public_job(job, jobs)
        row["last_successful_at"] = latest_success.get(job["account_connection_id"])
        result.append(row)
    return result


@router.post("/{org_id}/connections/{account_id}/jobs", status_code=202)
def create_job(org_id: OrgId, account_id: AccountId, body: CreateScan,
               actor: Principal, store: Organizations, dispatch: Dispatch):
    selection = None if body.mode == "full" else {"kind": body.mode}
    if body.pillar is not None:
        selection["pillar"] = body.pillar.value
    return enqueue_scan(org_id, account_id, body.request_id.hex, actor, store, dispatch, selection)


def enqueue_scan(org_id, account_id, request_id, actor, store, dispatch, verification=None):
    member = authorize(store, actor, org_id, SCAN_ROLES)
    connection = store.connection(org_id, account_id)
    if not connection or not has_account(member, connection["account_connection_id"]):
        raise HTTPException(404, "Connection not found.")
    allowed = os.environ.get("VERIFICATION_ALLOWED_ACCOUNTS", "")
    if allowed and account_id not in allowed.split(","):
        raise HTTPException(403, "This AWS account is outside the approved beta scope.")
    if connection["status"] != "verified":
        raise HTTPException(409, "Verify the connection before requesting a scan.")
    try:
        job = OrgJobs(store.table).enqueue(org_id, actor, connection, request_id, verification)
    except JobConflict:
        raise HTTPException(429, "A scan is active or the scan quota has been reached.") from None
    if job["state"] == "queued" and job["deadline"] > time.time():
        try:
            dispatch(org_id, job["job_id"])
        except (BotoCoreError, ClientError):
            raise HTTPException(503, "The scan queue is unavailable. Retry this request.") from None
    return public_job(job, OrgJobs(store.table))


@router.get("/{org_id}/jobs/{job_id}")
def get_job(org_id: OrgId, job_id: JobId, actor: Principal, store: Organizations):
    member = authorize(store, actor, org_id)
    jobs = OrgJobs(store.table)
    return public_job(scoped_job(jobs, org_id, job_id, member), jobs)


@router.get("/{org_id}/jobs/{job_id}/scopes")
def get_scopes(org_id: OrgId, job_id: JobId, actor: Principal, store: Organizations):
    member = authorize(store, actor, org_id)
    jobs = OrgJobs(store.table)
    scopes = scope_snapshot(jobs, scoped_job(jobs, org_id, job_id, member))
    return {"scopes": scopes, **summarize_scopes(scopes)}


@router.post("/{org_id}/jobs/{job_id}/retry-scope", status_code=202)
def retry_scope(org_id: OrgId, job_id: JobId, body: RetryScope,
                actor: Principal, store: Organizations, dispatch: Dispatch):
    member = authorize(store, actor, org_id, SCAN_ROLES)
    jobs = OrgJobs(store.table)
    source = scoped_job(jobs, org_id, job_id, member)
    state = public_job(source)["state"]
    allowed = (
        state in ("partial", "failed", "expired")
        and any(
            scope["check_id"] == body.check_id and scope["region"] == body.region
            and scope["status"] in ("incomplete", "failed", "expired")
            for scope in scope_snapshot(jobs, source)
        )
    )
    if not allowed:
        raise HTTPException(409, "Only an incomplete scope from a finished scan can be retried.")
    selection = {
        "check_id": body.check_id, "region": body.region, "retry_job_id": job_id, "kind": "scope_retry",
    }
    if previous_target := (source.get("verification") or {}).get("finding_id"):
        selection["finding_id"] = previous_target
    if not any(scope["region"] == body.region for scope in job_plan(source["region"], selection)):
        raise HTTPException(409, "That check scope is no longer available.")
    return enqueue_scan(org_id, source["aws_account_id"], body.request_id.hex, actor, store, dispatch, selection)


@router.get("/{org_id}/jobs/{job_id}/result")
def get_result(org_id: OrgId, job_id: JobId, actor: Principal, store: Organizations):
    member = authorize(store, actor, org_id)
    job = scoped_job(OrgJobs(store.table), org_id, job_id, member)
    if job["state"] not in ("complete", "partial"):
        raise HTTPException(409, "The scan has no published result.")
    result = ScanStore(store.table).get_scan(job["result_owner"], job["scan_id"], consistent=True)
    if not result:
        raise HTTPException(404, "The scan result has expired.")
    latest_member = authorize(store, actor, org_id)
    latest_job = scoped_job(OrgJobs(store.table), org_id, job_id, latest_member)
    if latest_job["state"] not in ("complete", "partial") or latest_job.get("result_owner") != job["result_owner"]:
        raise HTTPException(409, "The scan result changed. Reload and try again.")
    return result


@router.post("/{org_id}/jobs/{job_id}/cancel")
def cancel_job(org_id: OrgId, job_id: JobId, actor: Principal, store: Organizations):
    member = authorize(store, actor, org_id, SCAN_ROLES)
    jobs = OrgJobs(store.table)
    job = scoped_job(jobs, org_id, job_id, member)
    if job["actor"] != actor:
        authorize(store, actor, org_id, ("owner", "administrator"))
    try:
        jobs.cancel(job, actor)
    except JobConflict:
        raise HTTPException(409, "The scan is no longer active.") from None
    return {"state": "cancelled"}

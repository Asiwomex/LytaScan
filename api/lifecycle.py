"""Scoped finding workflow and history endpoints."""

import time
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, StringConstraints

from api.onboarding import AccountId, OrgId, Organizations, Principal
from api.org_jobs import Dispatch, ScanRequest, authorize, enqueue_scan, has_account
from scanner.lifecycle import EXCEPTIONS, WORKFLOW_ROLES, FindingConflict, FindingStore, effective_workflow

router = APIRouter(prefix="/v1/orgs")
FindingId = Annotated[str, Path(pattern=r"^[0-9a-f]{64}$")]
FilterStatus = Literal["open", "acknowledged", "in_progress", "resolved", "risk_accepted", "false_positive", "suppressed"]


class WorkflowChange(BaseModel):
    status: Literal["open", "acknowledged", "in_progress", "risk_accepted", "false_positive", "suppressed"]
    revision: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)] | None = None
    expires_at: int | None = None


class Comment(BaseModel):
    note: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


def access(store, actor, org, account_id, roles=None):
    member = authorize(store, actor, org) if roles is None else authorize(store, actor, org, roles)
    connection = store.connection(org, account_id)
    if not connection or not has_account(member, connection["account_connection_id"]):
        raise HTTPException(404, "Connection not found.")
    return connection["account_connection_id"]


def public(item):
    fields = (
        "finding_id", "check_id", "title", "pillar", "severity", "resource_arn", "region", "outcome",
        "outcome_reason", "first_seen", "last_seen", "last_observed_at", "rule_version", "registry_version",
        "evidence", "remediation", "resolution_reason", "exception_reason", "exception_until", "revision",
    )
    status = effective_workflow(item, int(time.time()))
    return {
        **{field: item.get(field) for field in fields},
        "workflow_status": status,
        "exception_reason": item.get("exception_reason") if status in EXCEPTIONS else None,
        "exception_until": item.get("exception_until") if status in EXCEPTIONS else None,
    }


@router.get("/{org_id}/connections/{account_id}/findings")
def list_findings(org_id: OrgId, account_id: AccountId, actor: Principal, store: Organizations,
                  status: FilterStatus | None = None, limit: Annotated[int, Query(ge=1, le=100)] = 50,
                  cursor: Annotated[str | None, Query(pattern=r"^[0-9a-f]{64}$")] = None):
    generation = access(store, actor, org_id, account_id)
    items, next_cursor = FindingStore(store.table).page(org_id, generation, status, limit, cursor)
    return {"findings": [public(item) for item in items], "next_cursor": next_cursor}


@router.get("/{org_id}/connections/{account_id}/findings/{finding_id}")
def detail(org_id: OrgId, account_id: AccountId, finding_id: FindingId, actor: Principal, store: Organizations):
    generation = access(store, actor, org_id, account_id)
    findings = FindingStore(store.table)
    item = findings.get(org_id, generation, finding_id)
    if not item:
        raise HTTPException(404, "Finding not found.")
    now = int(time.time())
    events = [{
        key: event.get(key) for key in ("event_id", "at", "action", "actor", "note", "previous_status", "workflow_status", "outcome")
    } for event in findings.history(org_id, generation, finding_id) if event["expires_at"] > now]
    return {**public(item), "history": list(reversed(events))}


@router.patch("/{org_id}/connections/{account_id}/findings/{finding_id}")
def update(org_id: OrgId, account_id: AccountId, finding_id: FindingId, body: WorkflowChange,
           actor: Principal, store: Organizations):
    generation = access(store, actor, org_id, account_id, WORKFLOW_ROLES)
    now = int(time.time())
    if body.status in EXCEPTIONS:
        if not body.reason or body.expires_at is None or not now < body.expires_at <= now + 90 * 86400:
            raise HTTPException(422, "An exception needs a reason and an expiry within the next 90 days.")
    elif body.expires_at is not None:
        raise HTTPException(422, "Expiry applies only to an exception.")
    findings = FindingStore(store.table)
    item = findings.get(org_id, generation, finding_id)
    if not item:
        raise HTTPException(404, "Finding not found.")
    try:
        return public(findings.change_workflow(item, actor, body.status, body.reason, body.expires_at, body.revision))
    except FindingConflict:
        raise HTTPException(409, "The finding changed. Reload before editing it.") from None


@router.post("/{org_id}/connections/{account_id}/findings/{finding_id}/verify", status_code=202)
def verify(org_id: OrgId, account_id: AccountId, finding_id: FindingId, body: ScanRequest,
           actor: Principal, store: Organizations, dispatch: Dispatch):
    generation = access(store, actor, org_id, account_id)
    item = FindingStore(store.table).get(org_id, generation, finding_id)
    if not item:
        raise HTTPException(404, "Finding not found.")
    return enqueue_scan(org_id, account_id, body.request_id.hex, actor, store, dispatch,
                        {"check_id": item["check_id"], "finding_id": finding_id})


@router.post("/{org_id}/connections/{account_id}/findings/{finding_id}/comments", status_code=201)
def comment(org_id: OrgId, account_id: AccountId, finding_id: FindingId, body: Comment,
            actor: Principal, store: Organizations):
    generation = access(store, actor, org_id, account_id, WORKFLOW_ROLES)
    findings = FindingStore(store.table)
    item = findings.get(org_id, generation, finding_id)
    if not item:
        raise HTTPException(404, "Finding not found.")
    try:
        findings.record_comment(item, actor, body.note)
    except FindingConflict:
        raise HTTPException(409, "The finding changed. Reload before commenting.") from None
    return {"status": "created"}

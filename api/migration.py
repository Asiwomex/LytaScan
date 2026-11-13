"""Owner-approved legacy history migration with a read-only preview."""

import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from api.onboarding import AccountId, OrgId, Organizations, Principal
from api.org_jobs import JobId, authorize, public_job, scoped_job
from scanner.migration import LegacyMigration, MigrationUnavailable
from scanner.org_jobs import JobConflict

router = APIRouter(prefix="/v1/orgs")


class ImportScan(BaseModel):
    scan_id: str = Field(pattern=r"^[0-9]{8}T[0-9]{6}Z$")


def verified_connection(store, org, account_id):
    account = store.connection(org, account_id)
    if not account or account["status"] != "verified":
        raise HTTPException(409, "Verify the destination AWS connection first.")
    return account


@router.get("/{org_id}/connections/{account_id}/migration")
def preview(org_id: OrgId, account_id: AccountId, actor: Principal, store: Organizations):
    authorize(store, actor, org_id, ("owner",))
    connection = verified_connection(store, org_id, account_id)
    migration = LegacyMigration(store.table)
    try:
        items = migration.source(actor, account_id)
    except MigrationUnavailable:
        return []
    result = []
    for item in reversed(items):
        if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", item["scan_id"]):
            continue
        _, job_id = migration.checkpoint(org_id, connection, actor, item["scan_id"])
        existing = migration.job(org_id, job_id)
        imported = existing and existing["state"] != "rolled_back"
        result.append({"scan_id": item["scan_id"], "started_at": item["started_at"],
                       "imported_job": job_id if imported else None})
    return result


@router.post("/{org_id}/connections/{account_id}/migration")
def migrate(org_id: OrgId, account_id: AccountId, body: ImportScan, actor: Principal, store: Organizations):
    authorize(store, actor, org_id, ("owner",))
    connection = verified_connection(store, org_id, account_id)
    try:
        return public_job(LegacyMigration(store.table).transfer(org_id, connection, actor, body.scan_id))
    except (MigrationUnavailable, JobConflict):
        raise HTTPException(409, "The legacy report is incomplete, expired, or its ownership could not be confirmed.") from None


@router.post("/{org_id}/jobs/{job_id}/rollback-import")
def rollback(org_id: OrgId, job_id: JobId, actor: Principal, store: Organizations):
    authorize(store, actor, org_id, ("owner",))
    migration = LegacyMigration(store.table)
    job = scoped_job(migration, org_id, job_id)
    try:
        migration.rollback(org_id, actor, job)
    except JobConflict:
        raise HTTPException(409, "This scan is not an active legacy import.") from None
    return {"state": "rolled_back"}

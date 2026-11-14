"""Bounded, attempt-scoped scan progress snapshots."""

from __future__ import annotations

import base64
import json
import time
import zlib
from threading import Lock
from collections.abc import Mapping
from typing import Any
from functools import lru_cache

from botocore.exceptions import ClientError

from scanner.engine import discover_checks, scope_plan
from scanner.organizations import member_check, org_key

SCOPES_PER_UPDATE_SECONDS = 1.0
ACTIVE_SCOPE = {"queued", "running"}
UNSUCCESSFUL_SCOPE = {"incomplete", "cancelled", "failed", "expired"}
QUICK_CHECKS = frozenset({
    "iam_root_mfa", "iam_root_access_keys", "ebs_default_encryption", "cloudtrail_multi_region",
    "cloudtrail_log_validation", "guardduty_enabled", "ec2_security_group_open_admin_ports", "rds_public_access",
})


class ProgressConflict(Exception):
    """The worker lost its scope progress write authority."""


@lru_cache(maxsize=1)
def check_catalog():
    return tuple(discover_checks(include_v2=True))


def job_checks(selection: Mapping[str, str] | None = None):
    checks = check_catalog()
    if not selection:
        return checks
    if selection.get("check_id"):
        return [check for check in checks if check.meta.check_id == selection["check_id"]]
    if selection.get("kind") == "quick":
        return [check for check in checks if check.meta.check_id in QUICK_CHECKS]
    return [check for check in checks if check.meta.pillar.value == selection["pillar"]]


def job_plan(region: str, selection: Mapping[str, str] | None = None) -> list[dict[str, str]]:
    return scope_plan(job_checks(selection), [region])


def _scope_key(scope: Mapping[str, Any]) -> str:
    return f"{scope['check_id']}:{scope['region']}"


def summarize_scopes(scopes: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "total": len(scopes),
        "settled": sum(scope["status"] not in ACTIVE_SCOPE for scope in scopes),
        "running": sum(scope["status"] == "running" for scope in scopes),
        "incomplete": sum(scope["status"] in UNSUCCESSFUL_SCOPE for scope in scopes),
    }


def scope_snapshot(store, job: dict[str, Any]) -> list[dict[str, Any]]:
    if job.get("source") == "legacy" or (
        not job.get("progress_schema_version") and not job.get("attempt")
    ):
        return []
    plan = job_plan(job["region"], job.get("verification"))
    key = org_key(job["organization_id"], f"JOB_PROGRESS#{job['job_id']}")
    saved = store._get(key) if job.get("attempt") else None
    updates = {}
    if saved and saved["attempt"] == job["attempt"]:
        updates = json.loads(zlib.decompress(base64.b64decode(saved["payload"])))
        plan = updates["plan"]
        updates = updates["scopes"]
    elif job["state"] in ("complete", "partial") and job.get("scope_progress") is None:
        # Jobs created before progress tracking have no attempt snapshots.
        return []
    state = job["state"]
    if state in ("queued", "running") and job.get("deadline", 0) <= time.time():
        state = "expired"
    scopes = []
    for planned in plan:
        scope = {**planned, "status": "queued", **updates.get(_scope_key(planned), {})}
        if scope["status"] in ACTIVE_SCOPE and state in ("cancelled", "failed", "expired"):
            scope["status"] = state
            scope["finished_at"] = int(job.get("finished_at") or job.get("deadline", 0))
        scopes.append(scope)
    return scopes


def job_scope_summary(store, job: dict[str, Any]) -> dict[str, int] | None:
    if job.get("source") == "legacy":
        return None
    if job.get("scope_progress") is not None and job["state"] in ("complete", "partial"):
        return job["scope_progress"]
    scopes = scope_snapshot(store, job)
    return summarize_scopes(scopes) if scopes else None


class ScopeProgress:
    """Serialize worker events and rate-limit writes to the provisioned table."""

    def __init__(self, store, job: dict[str, Any], attempt: str, roles: tuple[str, ...]):
        self.store = store
        self.job = job
        self.attempt = attempt
        self.roles = roles
        self.plan = job_plan(job["region"], job.get("verification"))
        self.planned_keys = {_scope_key(scope) for scope in self.plan}
        self.scopes: dict[str, dict[str, Any]] = {}
        self.last_flush = float("-inf")
        self.dirty = False
        self._probe_lock = Lock()

    def __call__(self, update: dict[str, Any]) -> None:
        key = _scope_key(update)
        if key not in self.planned_keys:
            raise ValueError("The scan reported a scope outside the job plan.")
        scope = self.scopes.setdefault(key, {})
        timestamp = int(time.time())
        status = update["status"]
        if status == "running":
            scope.update(status=status, started_at=timestamp)
        elif status in ("complete", "incomplete"):
            scope.update(status=status, finished_at=timestamp,
                         counts=update.get("counts", {}), reason_codes=update.get("reason_codes", []))
        else:
            raise ValueError("The scan reported an unsupported scope status.")
        self.dirty = True
        elapsed = time.monotonic() - self.last_flush
        if elapsed >= SCOPES_PER_UPDATE_SECONDS:
            self.flush()

    def flush(self) -> None:
        if not self.dirty:
            return
        job = self.job
        org = job["organization_id"]
        generation = job["account_connection_id"]
        table_name = self.store.table.name
        data = json.dumps({"plan": self.plan, "scopes": self.scopes}, separators=(",", ":")).encode()
        payload = base64.b64encode(zlib.compress(data)).decode("ascii")
        try:
            self.store._transact(
                member_check(self.store.table, job["actor"], org, self.roles, generation),
                self.store.connection_check(org, job["aws_account_id"], generation),
                {"ConditionCheck": {
                    "TableName": table_name, "Key": org_key(org, f"JOB#{job['job_id']}"),
                    "ConditionExpression": "#state = :running AND attempt = :attempt AND lease_until > :now",
                    "ExpressionAttributeNames": {"#state": "state"},
                    "ExpressionAttributeValues": {
                        ":running": "running", ":attempt": self.attempt, ":now": int(time.time()),
                    },
                }},
                {"Put": {
                    "TableName": table_name,
                    "Item": {
                        **org_key(org, f"JOB_PROGRESS#{job['job_id']}"), "attempt": self.attempt,
                        "account_connection_id": generation, "payload": payload, "expires_at": job["expires_at"],
                    },
                }},
            )
        except ClientError as error:
            reasons = {reason.get("Code") for reason in error.response.get("CancellationReasons", [])}
            if "ConditionalCheckFailed" in reasons:
                raise ProgressConflict from None
            raise
        self.dirty = False
        self.last_flush = time.monotonic()

    def probe(self) -> bool:
        """Check cancellation/authority at a sustained cadence during inventory."""
        with self._probe_lock:
            return self._probe()

    def _probe(self) -> bool:
        if time.monotonic() - self.last_flush < SCOPES_PER_UPDATE_SECONDS:
            return True
        job = self.job
        org = job["organization_id"]
        current = self.store.job(org, job["job_id"])
        member = self.store.membership(job["actor"], org)
        connection = self.store.connection(org, job["aws_account_id"])
        if not (
            current and current["state"] == "running" and current["attempt"] == self.attempt
            and current["lease_until"] > time.time() and member and member["role"] in self.roles
            and (member["role"] != "engineer" or member.get("allowed_account") == job["account_connection_id"])
            and connection and connection["account_connection_id"] == job["account_connection_id"]
            and connection["status"] == "verified"
        ):
            raise ProgressConflict
        self.last_flush = time.monotonic()
        return True

    def summary(self) -> dict[str, int]:
        return summarize_scopes([
            {"status": "queued", **self.scopes.get(_scope_key(scope), {})}
            for scope in self.plan
        ])

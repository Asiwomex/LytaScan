"""Finding records and audit history, separate from immutable scan evaluations."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

from scanner.findings import format_timestamp
from scanner.deletion_inventory import inventory_region, valid_identity
from scanner.organizations import OrganizationStore, connection_key, member_check, org_key

WORKFLOW_ROLES = ("owner", "administrator", "engineer", "security_analyst")
EXCEPTIONS = {"risk_accepted", "false_positive", "suppressed"}
UNAVAILABLE = {"error", "unknown", "skipped", "not_applicable"}
OUTCOME_PRIORITY = {"fail": 3, "error": 2, "unknown": 2, "skipped": 2, "not_applicable": 2, "pass": 1}
HISTORY_RETENTION = 90 * 86400


class FindingConflict(Exception):
    pass


def fingerprint(org: str, generation: str, evaluation: dict[str, Any]) -> str:
    arn = (evaluation.get("resource_id") or evaluation["resource_arn"]).removesuffix(":*").strip()
    parts = arn.split(":", 5)
    region = evaluation["region"]
    if len(parts) == 6:
        parts[:3] = [value.lower() for value in parts[:3]]
        arn = ":".join(parts)
        if parts[3]:
            region = parts[3]
        elif parts[2] in ("iam", "s3", "cloudfront") and parts[5] != "root":
            region = "global"
    identity = json.dumps([1, org, generation, evaluation["check_id"], arn, region], separators=(",", ":"))
    return hashlib.sha256(identity.encode()).hexdigest()


def effective_workflow(item: dict[str, Any], now: int) -> str:
    if item["workflow_status"] in EXCEPTIONS and item.get("exception_until", now + 1) <= now:
        return "open"
    return item["workflow_status"]


def _without_exception(item: dict[str, Any]) -> None:
    for key in ("exception_until", "exception_reason", "exception_actor"):
        item.pop(key, None)


class FindingStore(OrganizationStore):
    @staticmethod
    def _prefix(generation: str) -> str:
        return f"FINDING#{generation}#"

    def get(self, org: str, generation: str, finding_id: str) -> dict[str, Any] | None:
        return self._get(org_key(org, self._prefix(generation) + finding_id))

    def history(self, org: str, generation: str, finding_id: str) -> list[dict[str, Any]]:
        return self._list(f"ORG#{org}", f"FINDING_EVENT#{generation}#{finding_id}#")

    def inventory_types(self, org: str, generation: str) -> set[str]:
        return {
            item["resource_type"]
            for item in self._list(f"ORG#{org}", self._prefix(generation))
            if item["workflow_status"] != "resolved"
            and self._inventory_identity(item) is not None
        }

    @staticmethod
    def _inventory_identity(item):
        kind = item["resource_type"]
        region = inventory_region(kind, item["region"])
        arn = (item.get("resource_id") or item["resource_arn"]).strip().removesuffix(":*")
        account = item.get("aws_account_id") or item.get("account_id")
        if region and account and valid_identity(kind, account, region, arn):
            return kind, region, arn
        return None

    def page(self, org, generation, status, limit, cursor):
        prefix = self._prefix(generation)
        params = {
            "KeyConditionExpression": Key("PK").eq(f"ORG#{org}") & Key("SK").begins_with(prefix),
            "ConsistentRead": True,
        }
        if cursor:
            params["ExclusiveStartKey"] = org_key(org, prefix + cursor)
        now = int(time.time())
        result = []
        while len(result) < limit:
            page = self.table.query(**params, Limit=limit - len(result))
            result.extend(item for item in page["Items"] if not status or effective_workflow(item, now) == status)
            key = page.get("LastEvaluatedKey")
            if not key:
                return result, None
            params["ExclusiveStartKey"] = key
        return result, key["SK"].removeprefix(prefix)

    def _save(self, record, previous, event, *guards):
        put = {"TableName": self.table.name, "Item": record}
        if previous:
            put.update(ConditionExpression="revision = :previous",
                       ExpressionAttributeValues={":previous": previous["revision"]})
        else:
            put["ConditionExpression"] = "attribute_not_exists(PK)"
        actions = [*guards, {"Put": put}]
        if event:
            actions.append({"Put": {"TableName": self.table.name, "Item": event}})
        try:
            self._transact(*actions)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            raise FindingConflict from None

    def _event(self, item, *, action, actor, now, previous, note=None):
        event_id = uuid4().hex
        at = format_timestamp(datetime.fromtimestamp(now, timezone.utc))
        key = f"FINDING_EVENT#{item['generation']}#{item['finding_id']}#{int(item['event_sequence']):010d}"
        return {
            **org_key(item["organization_id"], key), "event_id": event_id, "at": at,
            "action": action, "actor": actor, "note": note,
            "previous_status": previous, "workflow_status": item["workflow_status"],
            "outcome": item["outcome"], "expires_at": now + HISTORY_RETENTION,
        }

    def _connection_guard(self, org, account, generation):
        return {"ConditionCheck": {
            "TableName": self.table.name, "Key": connection_key(org, account),
            "ConditionExpression": "account_connection_id = :generation",
            "ExpressionAttributeValues": {":generation": generation},
        }}

    def observe(self, job: dict[str, Any], report: dict[str, Any]) -> None:
        scan = report["scan"]
        assessment = scan.get("assessment")
        if not assessment:
            return
        org, generation = job["organization_id"], job["account_connection_id"]
        evaluations: dict[str, dict[str, Any]] = {}
        complete = {(scope["check_id"], scope["region"]) for scope in assessment.get("scopes", []) if scope["outcome"] == "complete"}
        existing = {item["finding_id"]: item for item in self._list(f"ORG#{org}", self._prefix(generation))}
        observed_resources = set()
        for raw in report["findings"]:
            if (identity := self._inventory_identity(raw)) is not None:
                observed_resources.add(identity)
            finding = raw
            if raw["status"] == "pass" and not any(
                (raw["check_id"], region) in complete for region in (raw["region"], "global")
            ):
                finding = {**raw, "status": "unknown", "reason_code": "incomplete_scope"}
            key = fingerprint(org, generation, finding)
            if key not in existing and finding["status"] != "fail":
                continue
            previous = evaluations.get(key)
            if not previous or OUTCOME_PRIORITY[finding["status"]] > OUTCOME_PRIORITY[previous["status"]]:
                evaluations[key] = finding
        if not (job.get("verification") or job.get("retry_scopes")):
            self._add_deletion_evaluations(job, report, existing, evaluations, complete, observed_resources)
        for finding_id, evaluation in evaluations.items():
            self._observe_one(job, scan, finding_id, evaluation)

    def _add_deletion_evaluations(self, job, report, existing, evaluations, complete, observed_resources):
        account = job["aws_account_id"]
        if report["scan"].get("account_id") != account:
            return
        inventory = {}
        ambiguous = set()
        for scope in report.get("inventory", ()):
            key = (scope.get("resource_type"), scope.get("region"))
            if key in inventory:
                ambiguous.add(key)
            inventory[key] = scope
        verified = {}
        for key, scope in inventory.items():
            identifiers = scope.get("resource_ids")
            if (key in ambiguous or scope.get("account_id") != account or scope.get("complete") is not True
                or not isinstance(identifiers, list) or inventory_region(*key) != key[1]
                or any(not isinstance(arn, str) or not valid_identity(*(
                    key[0], account, key[1], arn
                )) for arn in identifiers)):
                continue
            verified[key] = set(identifiers)
        for finding_id, item in existing.items():
            if finding_id in evaluations or item["workflow_status"] == "resolved":
                continue
            identity = self._inventory_identity(item)
            if not identity or identity in observed_resources:
                continue
            kind, region, arn = identity
            if ((item["check_id"], region) not in complete
                or (kind, region) not in verified
                or arn in verified[(kind, region)]):
                continue
            evaluations[finding_id] = {
                **item, "status": "not_applicable", "reason_code": "resource_deleted",
            }

    def _observe_one(self, job, scan, finding_id, evaluation):
        org, generation = job["organization_id"], job["account_connection_id"]
        account = job["aws_account_id"]
        observed_at = scan["finished_at"]
        now = int(time.time())
        outcome = evaluation["status"]
        for _ in range(4):
            previous = self.get(org, generation, finding_id)
            if previous and (
                previous["last_job"] == job["job_id"]
                or previous["last_observed_at"] > observed_at
                or previous.get("last_claimed_at", 0) > (job.get("started_at") or 0)
            ):
                return
            if not previous and outcome != "fail":
                return
            item = dict(previous or {
                **org_key(org, self._prefix(generation) + finding_id), "organization_id": org,
                "generation": generation, "finding_id": finding_id, "aws_account_id": account,
                "fingerprint_version": 1, "first_seen": observed_at, "workflow_status": "open",
                "event_sequence": 0,
            })
            previous_workflow = item["workflow_status"] if previous else None
            item["workflow_status"] = effective_workflow(item, now)
            if item["workflow_status"] != previous_workflow:
                _without_exception(item)
            action = "opened" if not previous else None
            deleted = evaluation.get("reason_code") == "resource_deleted"
            if (outcome == "pass" or deleted) and item["workflow_status"] != "resolved":
                item["workflow_status"] = "resolved"
                item["resolution_reason"] = "resource_deleted" if deleted else "confirmed_pass"
                _without_exception(item)
                action = "resolved"
            elif outcome == "fail":
                item["last_seen"] = observed_at
                if item["workflow_status"] == "resolved":
                    item["workflow_status"] = "open"
                    item.pop("resolution_reason", None)
                    action = "reopened"
            if previous and not action and (
                previous["outcome"] != outcome or previous_workflow != item["workflow_status"]
            ):
                action = "evaluation_changed"
            item.update(
                outcome=outcome, last_observed_at=observed_at, last_job=job["job_id"],
                last_claimed_at=job.get("started_at") or 0,
                rule_version=evaluation.get("rule_version", "1.0.0"),
                registry_version=scan["assessment"]["registry_version"], revision=uuid4().hex,
                **{key: evaluation[key] for key in (
                    "check_id", "title", "pillar", "severity", "region", "resource_arn", "resource_type", "remediation",
                )},
            )
            if evaluation.get("resource_id"):
                item["resource_id"] = evaluation["resource_id"]
            # Keep confirmed evidence when a later read is unavailable.
            if outcome not in UNAVAILABLE:
                item["evidence"] = evaluation["description"][:2000]
            item["outcome_reason"] = evaluation.get("reason_code") or (
                "evaluation_unavailable" if outcome in ("error", "unknown", "skipped") else None
            )
            event = None
            if action:
                item["event_sequence"] = item.get("event_sequence", 0) + 1
                event = self._event(
                    item, action=action, actor="scanner", now=now, previous=previous_workflow,
                    note="Resource absence confirmed by a complete inventory." if deleted else None,
                )
            job_guard = {"ConditionCheck": {
                "TableName": self.table.name, "Key": org_key(org, f"JOB#{job['job_id']}"),
                "ConditionExpression": "account_connection_id = :generation AND result_owner = :result",
                "ExpressionAttributeValues": {":generation": generation, ":result": job["result_owner"]},
            }}
            try:
                self._save(item, previous, event, self._connection_guard(org, account, generation), job_guard)
                return
            except FindingConflict:
                connection = self.connection(org, account)
                if not connection or connection["account_connection_id"] != generation:
                    return
        raise FindingConflict

    def change_workflow(self, item, actor, status, reason, until, expected_revision):
        if item["revision"] != expected_revision or item["workflow_status"] == "resolved":
            raise FindingConflict
        now = int(time.time())
        record = {**item, "workflow_status": status, "revision": uuid4().hex,
                  "event_sequence": item.get("event_sequence", 0) + 1}
        _without_exception(record)
        if status in EXCEPTIONS:
            record.update(exception_reason=reason, exception_actor=actor, exception_until=until)
        org, generation = item["organization_id"], item["generation"]
        event = self._event(record, action="workflow_changed", actor=actor, now=now,
                            previous=effective_workflow(item, now), note=reason)
        self._save(record, item, event, self._connection_guard(org, item["aws_account_id"], generation),
                   member_check(self.table, actor, org, WORKFLOW_ROLES, generation))
        return record

    def record_comment(self, item, actor, note):
        org, generation = item["organization_id"], item["generation"]
        record = {**item, "revision": uuid4().hex, "event_sequence": item.get("event_sequence", 0) + 1}
        event = self._event(record, action="commented", actor=actor, now=int(time.time()),
                            previous=item["workflow_status"], note=note)
        self._save(record, item, event, self._connection_guard(org, item["aws_account_id"], generation),
                   member_check(self.table, actor, org, WORKFLOW_ROLES, generation))

    def purge(self, org: str, generation: str) -> None:
        prefixes = (self._prefix(generation), f"FINDING_EVENT#{generation}#")
        for prefix in prefixes:
            with self.table.batch_writer() as batch:
                for item in self._list(f"ORG#{org}", prefix):
                    batch.delete_item(Key={"PK": item["PK"], "SK": item["SK"]})

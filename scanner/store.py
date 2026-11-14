"""Scans stored in DynamoDB, in one table.

Two kinds of item hold scans:

    PK = ACCOUNT#<owner>           SK = SCAN#<scan_id>      one summary per scan
    PK = SCAN#<owner>#<scan_id>    SK = FINDING#<00042>     one item per finding

The owner says whose scans these are. For the public scans it is the
scrubbed account ID, 000000000000. For a signed-in user's scans it is that
user and account together (see scanner/accounts.py), so one user can never
read another's.

Scan IDs are the scan's start time (20261009T221200Z), so they sort by
time. That makes "the latest scans for an owner" a single query on the
first key, newest first, and "every finding of a scan" a single query on
the second. Nothing ever needs a table scan.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from scanner.score import posture_score

RETENTION = timedelta(days=90)
INVENTORY_CHUNK_SIZE = 200
SUMMARY_FIELDS = (
    "scan_id",
    "account_id",
    "started_at",
    "finished_at",
    "regions",
    "checks_run",
    "score",
    "passed",
    "failed",
    "errored",
    "failed_by_severity",
)


def scan_id_for(started_at: str) -> str:
    """2026-10-09T22:12:00Z -> 20261009T221200Z"""
    return started_at.replace("-", "").replace(":", "")


def _plain(value: Any) -> Any:
    """DynamoDB returns every number as a Decimal; turn them back into ints."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


def summarise(report: dict[str, Any]) -> dict[str, Any]:
    scan = report["scan"]
    findings = report["findings"]
    by_status = Counter(finding["status"] for finding in findings)
    failed_by_severity = Counter(
        finding["severity"] for finding in findings if finding["status"] == "fail"
    )
    result = {
        "scan_id": scan_id_for(scan["started_at"]),
        "account_id": scan["account_id"],
        "started_at": scan["started_at"],
        "finished_at": scan["finished_at"],
        "regions": scan["regions"],
        "checks_run": scan["checks_run"],
        "score": posture_score(findings),
        "passed": by_status["pass"],
        "failed": by_status["fail"],
        "errored": by_status["error"],
        "failed_by_severity": dict(failed_by_severity),
    }
    if scan.get("assessment") is not None:
        result["assessment"] = scan["assessment"]
    return result


class ScanStore:
    def __init__(self, table: Any) -> None:
        self._table = table

    @classmethod
    def from_env(cls) -> ScanStore:
        return cls(boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"]))

    def put_scan(self, report: dict[str, Any], owner: str | None = None, *, expires_at: int | None = None) -> str:
        """Store a scan report as written by the scanner. Returns its scan ID.

        Without an owner the scan is filed under its own account ID, which
        is how the public, scrubbed scans are stored.
        """
        summary = summarise(report)
        if "assessment" in summary:
            summary["assessment"] = json.loads(json.dumps(summary["assessment"]), parse_float=Decimal)
        owner = owner or summary["account_id"]
        scan_id: str = summary["scan_id"]
        # DynamoDB deletes items once this time has passed, so the table
        # cannot grow without limit.
        expires_at = expires_at or int((datetime.now(timezone.utc) + RETENTION).timestamp())

        # batch_writer groups writes into batches of 25 and retries any
        # that DynamoDB could not take the first time.
        with self._table.batch_writer() as batch:
            partition = f"SCAN#{owner}#{scan_id}"
            for index, finding in enumerate(report["findings"]):
                batch.put_item(
                    Item={
                        **finding,
                        "PK": partition,
                        "SK": f"FINDING#{index:05d}",
                        "expires_at": expires_at,
                    }
                )
            for index, scope in enumerate(report.get("inventory", ())):
                base = {"PK": partition, "expires_at": expires_at}
                sk = f"INVENTORY#{index:06d}"
                ids = scope.get("resource_ids", [])
                # Resource identifiers can be long (for example IAM paths).
                # Refuse deletion evidence rather than store a truncated ID.
                valid_ids = isinstance(ids, list) and all(
                    isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 1500 for value in ids
                )
                if not valid_ids:
                    ids = []
                chunks = (len(ids) + INVENTORY_CHUNK_SIZE - 1) // INVENTORY_CHUNK_SIZE
                batch.put_item(Item={
                    **{key: scope[key] for key in ("resource_type", "region", "account_id", "reason_code") if key in scope},
                    **base, "SK": sk, "chunks": chunks, "complete": scope.get("complete") is True and valid_ids,
                })
                for n, offset in enumerate(range(0, len(ids), INVENTORY_CHUNK_SIZE)):
                    batch.put_item(Item={
                        **base, "SK": f"{sk}#{n:06d}", "resource_ids": ids[offset:offset + INVENTORY_CHUNK_SIZE],
                    })
        # Publish only after all evaluation and inventory batches finish.
        self._table.put_item(Item={
            **summary, "PK": f"ACCOUNT#{owner}", "SK": f"SCAN#{scan_id}", "expires_at": expires_at,
        })
        return scan_id

    def list_scans(self, owner: str, limit: int = 30) -> list[dict[str, Any]]:
        """Scan summaries for an owner, newest first."""
        response = self._table.query(
            KeyConditionExpression=Key("PK").eq(f"ACCOUNT#{owner}")
            & Key("SK").begins_with("SCAN#"),
            ScanIndexForward=False,
            Limit=limit,
        )
        return [self._summary(item) for item in response["Items"]]

    def get_scan(
        self, owner: str, scan_id: str, *, consistent: bool = False, include_inventory: bool = False,
    ) -> dict[str, Any] | None:
        """One scan in the shape the scanner writes, or None if it is unknown."""
        if scan_id == "latest":
            latest = self.list_scans(owner, limit=1)
            if not latest:
                return None
            summary = latest[0]
        else:
            response = self._table.get_item(
                Key={"PK": f"ACCOUNT#{owner}", "SK": f"SCAN#{scan_id}"},
                ConsistentRead=consistent,
            )
            if "Item" not in response:
                return None
            summary = self._summary(response["Item"])

        partition = f"SCAN#{owner}#{summary['scan_id']}"
        findings = self._findings(partition, consistent=consistent)
        if not findings and owner == summary["account_id"]:
            # Scans stored before owners existed used this shorter key.
            # They expire on their own 90 days after 2026-10-10.
            findings = self._findings(f"SCAN#{summary['scan_id']}")
        report = {"scan": summary, "findings": findings}
        if include_inventory:
            report["inventory"] = self._inventory(partition)
        return report

    def delete_scans(self, owner: str) -> int:
        """Delete every scan an owner has, findings included. Returns how many."""
        summaries = self._keys(f"ACCOUNT#{owner}")
        with self._table.batch_writer() as batch:
            for summary in summaries:
                scan_id = summary["SK"].removeprefix("SCAN#")
                for key in self._keys(f"SCAN#{owner}#{scan_id}"):
                    batch.delete_item(Key=key)
                batch.delete_item(Key=summary)
        return len(summaries)

    def _keys(self, partition: str) -> list[dict[str, str]]:
        """The keys of every item in a partition, without reading the items."""
        keys: list[dict[str, str]] = []
        query: dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(partition),
            "ProjectionExpression": "PK, SK",
            "ConsistentRead": True,
        }
        while True:
            page = self._table.query(**query)
            keys.extend(page["Items"])
            if "LastEvaluatedKey" not in page:
                return keys
            query["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def _findings(self, partition: str, *, consistent: bool = False) -> list[dict[str, Any]]:
        return [self._finding(item) for item in self._scan_rows(partition, "FINDING#", consistent)]

    def _scan_rows(self, partition: str, prefix: str, consistent: bool):
        query: dict[str, Any] = {
            "KeyConditionExpression": Key("PK").eq(partition) & Key("SK").begins_with(prefix),
            "ConsistentRead": consistent,
        }
        while True:
            page = self._table.query(**query)
            yield from page["Items"]
            if "LastEvaluatedKey" not in page:
                return
            query["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def _inventory(self, partition: str) -> list[dict[str, Any]]:
        rows = {row["SK"]: row for row in self._scan_rows(partition, "INVENTORY#", True)}
        scopes = []
        for sk, row in rows.items():
            if sk.count("#") != 1:
                continue
            keys = [f"{sk}#{index:06d}" for index in range(int(row["chunks"]))]
            scope = self._finding(row)
            scope.pop("chunks")
            scope["complete"] = scope.get("complete") is True and all(key in rows for key in keys)
            scope["resource_ids"] = [value for key in keys if key in rows for value in rows[key]["resource_ids"]]
            scopes.append(scope)
        return scopes

    @staticmethod
    def _summary(item: dict[str, Any]) -> dict[str, Any]:
        fields = (*SUMMARY_FIELDS, "assessment") if "assessment" in item else SUMMARY_FIELDS
        return {field: _plain(item.get(field)) for field in fields}

    @staticmethod
    def _finding(item: dict[str, Any]) -> dict[str, Any]:
        storage_only = {"PK", "SK", "expires_at"}
        return {key: _plain(value) for key, value in item.items() if key not in storage_only}

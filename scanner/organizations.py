"""Tenant-scoped records for the versioned onboarding API."""

from __future__ import annotations

import secrets
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from scanner.findings import format_timestamp

MANAGE_ACCOUNTS = frozenset({"owner", "administrator"})
MAX_CONNECTIONS = 3
VERIFY_INTERVAL = timedelta(seconds=30)


class ConnectionLimit(Exception):
    pass


class VerificationBusy(Exception):
    pass


class ConnectionChanged(Exception):
    pass


def org_key(org_id: str, item: str) -> dict[str, str]:
    return {"PK": f"ORG#{org_id}", "SK": item}


def membership_key(user_id: str, org_id: str) -> dict[str, str]:
    return {"PK": f"USER#{user_id}", "SK": f"ORG#{org_id}"}


def member_check(table: Any, actor: str, org_id: str, roles: tuple[str, ...], account: str | None = None) -> dict[str, Any]:
    values = {f":role{i}": role for i, role in enumerate(roles)}
    condition = f"#status = :active AND #role IN ({', '.join(values)})"
    if account is not None:
        condition += " AND (#role IN (:role0, :role1) OR allowed_account = :account)"
        values[":account"] = account
    return {"ConditionCheck": {
        "TableName": table.name,
        "Key": membership_key(actor, org_id),
        "ConditionExpression": condition,
        "ExpressionAttributeNames": {"#status": "status", "#role": "role"},
        "ExpressionAttributeValues": {":active": "active", **values},
    }}


def connection_key(org_id: str, account_id: str) -> dict[str, str]:
    return org_key(org_id, f"CONNECTION#{account_id}")


def _metadata(actor: str) -> dict[str, Any]:
    now = format_timestamp(datetime.now(timezone.utc))
    return {"schema_version": 1, "created_at": now, "updated_at": now, "created_by": actor}


class OrganizationStore:
    def __init__(self, table: Any) -> None:
        self.table = table

    def _get(self, key: dict[str, str]) -> dict[str, Any] | None:
        return self.table.get_item(Key=key, ConsistentRead=True).get("Item")

    def _list(self, partition: str, prefix: str) -> list[dict[str, Any]]:
        params = {
            "KeyConditionExpression": Key("PK").eq(partition) & Key("SK").begins_with(prefix),
            "ConsistentRead": True,
        }
        items = []
        while True:
            page = self.table.query(**params)
            items.extend(page["Items"])
            if "LastEvaluatedKey" not in page:
                return items
            params["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def _transact(self, *actions: dict[str, Any]) -> None:
        self.table.meta.client.transact_write_items(TransactItems=list(actions))

    def create(self, user_id: str, name: str, request_id: str) -> dict[str, Any]:
        org_id = uuid4().hex
        request_key = {"PK": f"USER#{user_id}", "SK": f"CREATE_ORG#{request_id}"}
        metadata = _metadata(user_id)
        org = {**org_key(org_id, "PROFILE"), **metadata, "organization_id": org_id, "name": name}
        member = {
            **membership_key(user_id, org_id), **metadata, "organization_id": org_id,
            "role": "owner", "status": "active",
        }
        request = {**request_key, "organization_id": org_id}
        try:
            self._transact(*(
                {"Put": {"TableName": self.table.name, "Item": item, "ConditionExpression": "attribute_not_exists(PK)"}}
                for item in (org, member, request)
            ))
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            previous = self._get(request_key)
            existing = previous and self._get(org_key(previous["organization_id"], "PROFILE"))
            if existing is None or self.role(user_id, existing["organization_id"]) != "owner":
                raise
            if existing["name"] != name:
                raise ValueError("This request was already used with another organization name.") from None
            return existing
        return org

    def role(self, user_id: str, org_id: str) -> str | None:
        member = self.membership(user_id, org_id)
        return member["role"] if member else None

    def membership(self, user_id: str, org_id: str) -> dict[str, Any] | None:
        member = self._get(membership_key(user_id, org_id))
        return member if member and member.get("status") == "active" else None

    def organizations(self, user_id: str) -> list[dict[str, Any]]:
        organizations = []
        for member in self._list(f"USER#{user_id}", "ORG#"):
            if member.get("status") == "active":
                org = self._get(org_key(member["organization_id"], "PROFILE"))
                if org:
                    organizations.append({**org, "role": member["role"]})
        return organizations

    def connections(self, org_id: str) -> list[dict[str, Any]]:
        return self._list(f"ORG#{org_id}", "CONNECTION#")

    def connection(self, org_id: str, account_id: str) -> dict[str, Any] | None:
        return self._get(connection_key(org_id, account_id))

    def _membership_check(self, actor: str, org_id: str) -> dict[str, Any]:
        return member_check(self.table, actor, org_id, ("owner", "administrator"))

    def connect(self, actor: str, org_id: str, account_id: str, name: str, region: str) -> dict[str, Any]:
        existing = self.connection(org_id, account_id)
        if existing:
            return existing
        connection_id = uuid4().hex
        suffix = f"-{secrets.token_hex(8)}"
        account = {
            **connection_key(org_id, account_id),
            **_metadata(actor),
            "organization_id": org_id,
            "account_connection_id": connection_id,
            "aws_account_id": account_id,
            "name": name,
            "region": region,
            "role_name_suffix": suffix,
            "role_arn": f"arn:aws:iam::{account_id}:role/PillarscanAuditRole{suffix}",
            "external_id": b64encode(secrets.token_bytes(32)).decode("ascii"),
            "status": "pending",
        }
        try:
            self._transact(
                self._membership_check(actor, org_id),
                {"Put": {
                    "TableName": self.table.name, "Item": account,
                    "ConditionExpression": "attribute_not_exists(PK)",
                }},
                {"Update": {
                    "TableName": self.table.name, "Key": org_key(org_id, "PROFILE"),
                    "UpdateExpression": "ADD connection_count :one",
                    "ConditionExpression": "attribute_exists(PK) AND (attribute_not_exists(connection_count) OR connection_count < :limit)",
                    "ExpressionAttributeValues": {":one": 1, ":limit": MAX_CONNECTIONS},
                }},
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            if self.role(actor, org_id) not in MANAGE_ACCOUNTS:
                raise ConnectionChanged from None
            existing = self.connection(org_id, account_id)
            if existing:
                return existing
            org = self._get(org_key(org_id, "PROFILE"))
            if org and org.get("connection_count", 0) >= MAX_CONNECTIONS:
                raise ConnectionLimit from None
            raise
        return account

    def begin_verification(self, account: dict[str, Any], actor: str) -> str:
        now = datetime.now(timezone.utc)
        attempt = uuid4().hex
        org_id = account["organization_id"]
        try:
            self._transact(
                self._membership_check(actor, org_id),
                {"Update": {
                    "TableName": self.table.name,
                    "Key": connection_key(org_id, account["aws_account_id"]),
                    "UpdateExpression": (
                        "SET verification_attempt = :attempt, verification_until = :until, "
                        "verification_actor = :actor, updated_at = :now"
                    ),
                    "ConditionExpression": (
                        "account_connection_id = :id AND (attribute_not_exists(verification_until) OR verification_until <= :now)"
                    ),
                    "ExpressionAttributeValues": {
                        ":id": account["account_connection_id"], ":attempt": attempt, ":actor": actor,
                        ":now": format_timestamp(now), ":until": format_timestamp(now + VERIFY_INTERVAL),
                    },
                }},
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            raise VerificationBusy from None
        return attempt

    def finish_verification(self, account: dict[str, Any], actor: str, attempt: str, status: str) -> dict[str, Any]:
        org_id = account["organization_id"]
        now = format_timestamp(datetime.now(timezone.utc))
        verified = status == "verified"
        update = "SET #status = :status, updated_at = :now"
        update += ", verified_at = :now" if verified else " REMOVE verified_at"
        try:
            self._transact(
                self._membership_check(actor, org_id),
                {"Update": {
                    "TableName": self.table.name,
                    "Key": connection_key(org_id, account["aws_account_id"]),
                    "UpdateExpression": update,
                    "ConditionExpression": (
                        "account_connection_id = :id AND verification_attempt = :attempt AND verification_actor = :actor"
                    ),
                    "ExpressionAttributeNames": {"#status": "status"},
                    "ExpressionAttributeValues": {
                        ":status": status, ":now": now, ":id": account["account_connection_id"],
                        ":attempt": attempt, ":actor": actor,
                    },
                }},
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            raise ConnectionChanged from None
        result = {**account, "status": status, "updated_at": now}
        result.pop("verified_at", None)
        if verified:
            result["verified_at"] = now
        return result

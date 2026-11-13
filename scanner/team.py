"""One-time, email-bound organization invitations."""

import hashlib
import secrets
import time
from datetime import datetime, timezone
from uuid import uuid4

from botocore.exceptions import ClientError

from scanner.findings import format_timestamp
from scanner.organizations import OrganizationStore, member_check, membership_key, org_key


class InviteConflict(Exception):
    pass


class TeamStore(OrganizationStore):
    def issue(self, org: str, actor: str, email: str, role: str, allowed_account: str | None):
        invite_id = uuid4().hex
        secret = secrets.token_urlsafe(32)
        now = int(time.time())
        invite = {
            **org_key(org, f"INVITE#{invite_id}"), "invite_id": invite_id,
            "email": email, "role": role, "status": "pending",
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "valid_until": now + 86400, "expires_at": now + 30 * 86400,
            "created_by": actor, "schema_version": 1,
            "allowed_account": allowed_account,
        }
        roles = ("owner",) if role == "administrator" else ("owner", "administrator")
        self._transact(member_check(self.table, actor, org, roles), {"Put": {
            "TableName": self.table.name, "Item": invite,
            "ConditionExpression": "attribute_not_exists(PK)",
        }})
        return {**invite, "token": f"{org}.{invite_id}.{secret}"}

    def invites(self, org: str):
        return self._list(f"ORG#{org}", "INVITE#")

    def revoke(self, org: str, actor: str, invite_id: str):
        try:
            self._transact(self._membership_check(actor, org), {"Update": {
                "TableName": self.table.name, "Key": org_key(org, f"INVITE#{invite_id}"),
                "UpdateExpression": "SET #state = :revoked REMOVE secret_hash",
                "ConditionExpression": "#state = :pending",
                "ExpressionAttributeNames": {"#state": "status"},
                "ExpressionAttributeValues": {":pending": "pending", ":revoked": "revoked"},
            }})
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            raise InviteConflict from None

    def accept(self, token: str, actor: str, email: str) -> str:
        org, invite_id, secret = token.split(".")
        key = org_key(org, f"INVITE#{invite_id}")
        invite = self._get(key)
        now = int(time.time())
        digest = hashlib.sha256(secret.encode()).hexdigest()
        if (
            not invite or invite["email"] != email or invite["valid_until"] <= now
            or invite["status"] != "pending" or not secrets.compare_digest(invite["secret_hash"], digest)
        ):
            raise InviteConflict
        member = {
            **membership_key(actor, org), "organization_id": org, "role": invite["role"],
            "status": "active", "schema_version": 1, "email": email,
            "created_at": format_timestamp(datetime.now(timezone.utc)), "created_by": invite["created_by"],
            "allowed_account": invite.get("allowed_account"),
        }
        try:
            self._transact(
                {"Update": {
                    "TableName": self.table.name, "Key": key,
                    "UpdateExpression": "SET #state = :accepted, accepted_by = :actor REMOVE secret_hash",
                    "ConditionExpression": "#state = :pending AND valid_until > :now AND secret_hash = :digest",
                    "ExpressionAttributeNames": {"#state": "status"},
                    "ExpressionAttributeValues": {
                        ":pending": "pending", ":accepted": "accepted", ":now": now,
                        ":digest": digest, ":actor": actor,
                    },
                }},
                {"Put": {
                    "TableName": self.table.name, "Item": member,
                    "ConditionExpression": "attribute_not_exists(PK)",
                }},
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            raise InviteConflict from None
        return org

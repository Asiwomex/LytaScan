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
    def members(self, org: str):
        profile = self._get(org_key(org, "PROFILE"))
        subjects = {profile.get("owner_id", profile["created_by"])} if profile else set()
        subjects.update(
            item["accepted_by"] for item in self.invites(org) if item.get("accepted_by")
        )
        subjects.update(item["member_id"] for item in self._list(f"ORG#{org}", "MEMBER#"))
        return [
            {"member_id": subject, **member}
            for subject in sorted(subjects)
            if (member := self.membership(subject, org))
        ]

    def edit_member(self, org, actor, target, *, role=None, account=None):
        if actor == target:
            raise InviteConflict
        current = self.membership(target, org)
        if not current or current["role"] == "owner":
            raise InviteConflict
        managers = ("owner",) if "administrator" in (current["role"], role) else ("owner", "administrator")
        values = {":active": "active", ":old": current["role"], ":now": format_timestamp(datetime.now(timezone.utc))}
        if role is None:
            update = "SET #status = :revoked, revoked_at = :epoch, updated_at = :now REMOVE allowed_account"
            values.update({":revoked": "revoked", ":epoch": int(time.time())})
        else:
            update = "SET #role = :role, allowed_account = :account, updated_at = :now"
            values.update({":role": role, ":account": account})
        self._change(
            member_check(self.table, actor, org, managers),
            {"Update": {
                "TableName": self.table.name, "Key": membership_key(target, org),
                "UpdateExpression": update, "ConditionExpression": "#status = :active AND #role = :old",
                "ExpressionAttributeNames": {"#status": "status", "#role": "role"},
                "ExpressionAttributeValues": values,
            }},
        )

    def transfer_owner(self, org, actor, target):
        if actor == target:
            raise InviteConflict
        self._change(
            {"Update": {
                "TableName": self.table.name, "Key": org_key(org, "PROFILE"),
                "UpdateExpression": "SET owner_id = :target",
                "ConditionExpression": "owner_id = :actor OR (attribute_not_exists(owner_id) AND created_by = :actor)",
                "ExpressionAttributeValues": {":target": target, ":actor": actor},
            }},
            *( {"Update": {
                "TableName": self.table.name, "Key": membership_key(subject, org),
                "UpdateExpression": "SET #role = :new REMOVE allowed_account",
                "ConditionExpression": "#status = :active AND #role = :old",
                "ExpressionAttributeNames": {"#status": "status", "#role": "role"},
                "ExpressionAttributeValues": {":active": "active", ":old": before, ":new": after},
            }} for subject, before, after in ((actor, "owner", "administrator"), (target, "administrator", "owner")) ),
            *({"Put": {"TableName": self.table.name,
                       "Item": {**org_key(org, f"MEMBER#{subject}"), "member_id": subject}}}
              for subject in (actor, target)),
        )

    def _change(self, *actions):
        try:
            self._transact(*actions)
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            raise InviteConflict from None

    def issue(self, org: str, actor: str, email: str, role: str, allowed_account: str | None):
        invite_id = uuid4().hex
        secret = secrets.token_urlsafe(32)
        now = int(time.time())
        invite = {
            **org_key(org, f"INVITE#{invite_id}"), "invite_id": invite_id,
            "email": email, "role": role, "status": "pending",
            "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
            "valid_until": now + 86400, "expires_at": now + 30 * 86400,
            "issued_at": now,
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
            issuer = invite["created_by"]
            if issuer == actor:
                raise InviteConflict
            issuer_roles = ("owner",) if invite["role"] == "administrator" else ("owner", "administrator")
            self._transact(
                member_check(self.table, issuer, org, issuer_roles),
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
                    "ConditionExpression": "attribute_not_exists(PK) OR (#status = :revoked AND revoked_at < :issued)",
                    "ExpressionAttributeNames": {"#status": "status"},
                    "ExpressionAttributeValues": {":revoked": "revoked", ":issued": invite.get("issued_at", invite["valid_until"] - 86400)},
                }},
                {"Put": {
                    "TableName": self.table.name,
                    "Item": {**org_key(org, f"MEMBER#{actor}"), "member_id": actor},
                }},
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            raise InviteConflict from None
        return org

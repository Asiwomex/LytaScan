"""Organization team invitations. The API returns a link token once."""

import json
import os
import time
from typing import Annotated, Literal
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, Request as UrlRequest, build_opener

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, Field
from botocore.exceptions import ClientError

from api.onboarding import OrgId, Organizations, Principal, require_manager
from scanner.team import InviteConflict, TeamStore

router = APIRouter(prefix="/v1/orgs")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def verified_email(request: Request) -> str:
    token = request.headers.get("authorization", "").partition(" ")[2]
    url = os.environ.get("COGNITO_USERINFO_URL")
    if not token or not url:
        raise HTTPException(503, "Email verification is unavailable.")
    try:
        with build_opener(NoRedirect()).open(
            UrlRequest(url, headers={"Authorization": f"Bearer {token}"}), timeout=5,
        ) as response:
            claims = json.loads(response.read(16384))
    except (URLError, TimeoutError, ValueError):
        raise HTTPException(503, "Email verification is unavailable.") from None
    gateway_claims = request.scope["aws.event"]["requestContext"]["authorizer"]["jwt"]["claims"]
    if claims.get("sub") != gateway_claims["sub"] or claims.get("email_verified") not in (True, "true") or not claims.get("email"):
        raise HTTPException(403, "Verify your email address before accepting an invitation.")
    return claims["email"].strip().lower()


class MemberAccess(BaseModel):
    role: Literal["administrator", "engineer", "viewer", "security_analyst", "finance_analyst"]
    allowed_account: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class InviteInput(MemberAccess):
    email: str = Field(max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


MemberId = Annotated[str, Path(pattern=r"^[a-zA-Z0-9_-]{1,128}$")]


def account_grant(store, org, body):
    if body.role == "administrator":
        return None
    if body.role == "finance_analyst" and body.allowed_account is None:
        return None
    if not any(item["account_connection_id"] == body.allowed_account for item in store.connections(org)):
        raise HTTPException(422, "Choose a connection for this role.")
    return body.allowed_account


@router.get("/{org_id}/members")
def list_members(org_id: OrgId, actor: Principal, store: Organizations):
    require_manager(store, actor, org_id)
    return [{
        "member_id": item["member_id"], "email": item.get("email"), "role": item["role"],
        "allowed_account": item.get("allowed_account"), "is_self": item["member_id"] == actor,
    } for item in TeamStore(store.table).members(org_id)]


def manage_target(store, org, actor, target, new_role=None):
    require_manager(store, actor, org)
    current = store.role(target, org)
    if not current:
        raise HTTPException(404, "Member not found.")
    if actor == target or current == "owner":
        raise HTTPException(409, "Transfer ownership before changing the owner. Managers cannot edit their own membership.")
    if "administrator" in (current, new_role) and store.role(actor, org) != "owner":
        raise HTTPException(403, "Only the owner can manage administrators.")


@router.patch("/{org_id}/members/{member_id}")
def edit_member(org_id: OrgId, member_id: MemberId, body: MemberAccess, actor: Principal, store: Organizations):
    manage_target(store, org_id, actor, member_id, body.role)
    try:
        TeamStore(store.table).edit_member(org_id, actor, member_id, role=body.role, account=account_grant(store, org_id, body))
    except InviteConflict:
        raise HTTPException(409, "Membership changed. Reload and try again.") from None
    return {"status": "updated"}


@router.delete("/{org_id}/members/{member_id}")
def remove_member(org_id: OrgId, member_id: MemberId, actor: Principal, store: Organizations):
    manage_target(store, org_id, actor, member_id)
    try:
        TeamStore(store.table).edit_member(org_id, actor, member_id)
    except InviteConflict:
        raise HTTPException(409, "Membership changed. Reload and try again.") from None
    return {"status": "revoked"}


@router.post("/{org_id}/members/{member_id}/transfer-ownership")
def transfer_owner(org_id: OrgId, member_id: MemberId, actor: Principal, store: Organizations):
    require_manager(store, actor, org_id)
    if store.role(actor, org_id) != "owner":
        raise HTTPException(403, "Only the owner can transfer ownership.")
    try:
        TeamStore(store.table).transfer_owner(org_id, actor, member_id)
    except InviteConflict:
        raise HTTPException(409, "Select an active administrator to become the new owner.") from None
    return {"status": "transferred"}


class InviteToken(BaseModel):
    token: str = Field(pattern=r"^[0-9a-f]{32}\.[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$")


class InviteId(BaseModel):
    invite_id: str = Field(pattern=r"^[0-9a-f]{32}$")


def public_invite(invite):
    return {
        "invite_id": invite["invite_id"], "email": invite["email"], "role": invite["role"],
        "valid_until": int(invite["valid_until"]),
        "allowed_account": invite.get("allowed_account"),
        "status": "expired" if invite["status"] == "pending" and invite["valid_until"] <= time.time() else invite["status"],
    }


@router.get("/{org_id}/invites")
def list_invites(org_id: OrgId, actor: Principal, store: Organizations):
    require_manager(store, actor, org_id)
    return [public_invite(item) for item in TeamStore(store.table).invites(org_id)]


@router.post("/{org_id}/invites", status_code=201)
def issue_invite(org_id: OrgId, body: InviteInput, actor: Principal, store: Organizations):
    require_manager(store, actor, org_id)
    if body.role == "administrator" and store.role(actor, org_id) != "owner":
        raise HTTPException(403, "Only an owner can invite administrators.")
    try:
        invite = TeamStore(store.table).issue(org_id, actor, body.email.lower(), body.role, account_grant(store, org_id, body))
    except ClientError as error:
        if error.response["Error"]["Code"] != "TransactionCanceledException":
            raise
        raise HTTPException(409, "Invitation creation conflicted with another change. Try again.") from None
    return {**public_invite(invite), "token": invite["token"]}


@router.post("/{org_id}/invites/revoke")
def revoke_invite(org_id: OrgId, body: InviteId, actor: Principal, store: Organizations):
    require_manager(store, actor, org_id)
    try:
        TeamStore(store.table).revoke(org_id, actor, body.invite_id)
    except InviteConflict:
        raise HTTPException(409, "This invitation is no longer pending.") from None
    return {"status": "revoked"}


@router.post("/invites/accept")
def accept_invite(body: InviteToken, actor: Principal, store: Organizations,
                  email: Annotated[str, Depends(verified_email)]):
    try:
        org = TeamStore(store.table).accept(body.token, actor, email)
    except InviteConflict:
        raise HTTPException(409, "This invitation cannot be accepted. Check the link and signed-in email.") from None
    return {"organization_id": org}

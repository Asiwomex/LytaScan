"""Organization team invitations. The API returns a link token once."""

import json
import os
import time
from typing import Annotated, Literal
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, Request as UrlRequest, build_opener

from fastapi import APIRouter, Depends, HTTPException, Request
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


class InviteInput(BaseModel):
    email: str = Field(max_length=254, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    role: Literal["administrator", "engineer", "viewer", "security_analyst", "finance_analyst"]
    allowed_account: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


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
    if body.role in ("engineer", "viewer", "security_analyst") and not any(
        item["account_connection_id"] == body.allowed_account for item in store.connections(org_id)
    ):
        raise HTTPException(422, "Choose a connection for this role.")
    try:
        invite = TeamStore(store.table).issue(org_id, actor, body.email.lower(), body.role, body.allowed_account)
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

"""Versioned organization and account onboarding endpoints."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from functools import lru_cache
from typing import Annotated, Any, Literal
from urllib.parse import urlencode
from uuid import UUID

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from pydantic import BaseModel, Field, StringConstraints
from api.connection_cleanup import get_cleanup_dispatcher

from scanner.organizations import (
    MANAGE_ACCOUNTS,
    ConnectionChanged,
    ConnectionLimit,
    OrganizationStore,
    VerificationBusy,
    org_key,
)

router = APIRouter(prefix="/v1/orgs")
Region = Literal["us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-west-2"]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]
OrgId = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]
AccountId = Annotated[str, Path(pattern=r"^[0-9]{12}$")]


class NewOrganization(BaseModel):
    name: Name
    request_id: UUID


class NewConnection(BaseModel):
    name: Name
    aws_account_id: str = Field(pattern=r"^[0-9]{12}$")
    region: Region
    read_access_consent: Literal[True]


class VerifyConnection(BaseModel):
    role_arn: str = Field(max_length=100)


class Organization(BaseModel):
    organization_id: str
    name: str
    role: str


class Connection(BaseModel):
    account_connection_id: str
    aws_account_id: str
    name: str
    region: Region
    role_arn: str
    status: Literal["pending", "verified", "failed"]
    verified_at: str | None = None


class ConnectionSetup(Connection):
    launch_url: str | None


def principal(request: Request) -> str:
    claims = request.scope.get("aws.event", {}).get("requestContext", {}).get(
        "authorizer", {}
    ).get("jwt", {}).get("claims", {})
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject or claims.get("token_use") != "access":
        raise HTTPException(401, "Sign in first.")
    return subject


@lru_cache
def get_organizations() -> OrganizationStore:
    return OrganizationStore(boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"]))


def get_setup_url() -> Callable[[dict[str, Any]], str | None]:
    def url(account: dict[str, Any]) -> str:
        region = os.environ.get("AWS_REGION", "us-east-1")
        params = urlencode({
            "templateURL": os.environ["ROLE_TEMPLATE_URL"],
            "stackName": f"pillarscan-audit-role{account['role_name_suffix']}",
            "param_ScannerPrincipalArn": os.environ["SCANNER_ROLE_ARN"],
            "param_ExternalId": account["external_id"],
            "param_RoleNameSuffix": account["role_name_suffix"],
        })
        return f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/quickcreate?{params}"
    return url


@lru_cache
def get_verifier() -> Callable[[dict[str, Any], str], str]:
    def invoke(account: dict[str, Any], attempt: str) -> str:
        try:
            client = boto3.client("lambda", config=Config(
                connect_timeout=2, read_timeout=24, retries={"total_max_attempts": 1},
            ))
            response = client.invoke(
                FunctionName=os.environ["SCANNER_FUNCTION_ARN"],
                Payload=json.dumps({
                    "operation": "verify_connection",
                    "organization_id": account["organization_id"],
                    "aws_account_id": account["aws_account_id"],
                    "account_connection_id": account["account_connection_id"],
                    "verification_attempt": attempt,
                }).encode(),
            )
            with response["Payload"] as payload:
                if response.get("FunctionError"):
                    return "unavailable"
                data = json.load(payload)
                result = data.get("result") if isinstance(data, dict) else None
                return result if isinstance(result, str) else "unavailable"
        except (BotoCoreError, ClientError, ValueError):
            return "unavailable"
    return invoke


Principal = Annotated[str, Depends(principal)]
Organizations = Annotated[OrganizationStore, Depends(get_organizations)]
SetupUrl = Annotated[Callable[[dict[str, Any]], str | None], Depends(get_setup_url)]
Verifier = Annotated[Callable[[dict[str, Any], str], str], Depends(get_verifier)]


def require_manager(store: OrganizationStore, user: str, org_id: str) -> None:
    role = store.role(user, org_id)
    if role is None:
        raise HTTPException(404, "Organization not found.")
    if role not in MANAGE_ACCOUNTS:
        raise HTTPException(403, "An organization owner or administrator must manage connections.")


@router.get("", response_model=list[Organization])
def list_organizations(user: Principal, store: Organizations) -> list[dict[str, Any]]:
    return store.organizations(user)


@router.post("", response_model=Organization, status_code=201)
def create_organization(body: NewOrganization, user: Principal, store: Organizations) -> dict[str, Any]:
    try:
        return {**store.create(user, body.name, body.request_id.hex), "role": "owner"}
    except ValueError as error:
        raise HTTPException(409, str(error)) from None


@router.get("/{org_id}/connections", response_model=list[Connection])
def list_connections(org_id: OrgId, user: Principal, store: Organizations) -> list[dict[str, Any]]:
    member = store.membership(user, org_id)
    if not member:
        raise HTTPException(404, "Organization not found.")
    if member["role"] not in (*MANAGE_ACCOUNTS, "engineer", "viewer", "security_analyst"):
        raise HTTPException(403, "Your role cannot view AWS connections.")
    return [item for item in store.connections(org_id) if
            member["role"] in MANAGE_ACCOUNTS or member.get("allowed_account") == item["account_connection_id"]]


@router.post("/{org_id}/connections", response_model=ConnectionSetup, status_code=201)
def create_connection(
    org_id: OrgId, body: NewConnection, user: Principal, store: Organizations, setup_url: SetupUrl,
) -> dict[str, Any]:
    require_manager(store, user, org_id)
    allowed = os.environ.get("VERIFICATION_ALLOWED_ACCOUNTS", "")
    if allowed and body.aws_account_id not in allowed.split(","):
        raise HTTPException(403, "This AWS account is outside the approved beta scope.")
    try:
        account = store.connect(user, org_id, body.aws_account_id, body.name, body.region)
    except ConnectionLimit:
        raise HTTPException(409, "This organization has reached its connection limit.") from None
    except ConnectionChanged:
        raise HTTPException(409, "Organization access changed. Reload and try again.") from None
    if (account["name"], account["region"]) != (body.name, body.region):
        raise HTTPException(409, "This AWS account already has a connection with different settings.")
    return {**account, "launch_url": setup_url(account)}


@router.get("/{org_id}/connections/{account_id}/setup", response_model=ConnectionSetup)
def connection_setup(
    org_id: OrgId, account_id: AccountId, user: Principal, store: Organizations, setup_url: SetupUrl,
) -> dict[str, Any]:
    require_manager(store, user, org_id)
    account = store.connection(org_id, account_id)
    if not account:
        raise HTTPException(404, "Connection not found.")
    return {**account, "launch_url": setup_url(account)}


class RemoveConnection(BaseModel):
    connection_id: str = Field(pattern=r"^[0-9a-f]{32}$")


@router.post("/{org_id}/connections/{account_id}/disconnect", status_code=202)
def remove_connection(org_id: OrgId, account_id: AccountId, body: RemoveConnection,
                      user: Principal, store: Organizations,
                      dispatch: Annotated[Callable[[OrganizationStore, str, str], bool], Depends(get_cleanup_dispatcher)]) -> dict[str, Any]:
    require_manager(store, user, org_id)
    account = store.connection(org_id, account_id)
    if account and account["account_connection_id"] == body.connection_id:
        try:
            removed = store.remove_connection(user, org_id, account)
        except ConnectionChanged:
            raise HTTPException(409, "The connection changed. Reload and try again.") from None
    else:
        removed = store._get(org_key(org_id, f"REMOVED#{body.connection_id}"))
        if not removed or removed["aws_account_id"] != account_id:
            raise HTTPException(404, "Connection not found.")
    queued = dispatch(store, org_id, body.connection_id)
    return {
        "status": "disconnected", "cleanup_queued": queued,
        "stack_name": f"pillarscan-audit-role{removed['role_name_suffix']}",
    }


VERIFICATION_ERRORS = {
    "assume_denied": "AWS denied the role assumption. Check that the stack finished and trusts the scanner with this connection’s external ID.",
    "external_id_not_required": "The role accepts requests without the correct external ID. Replace its trust policy using the provided template.",
    "identity_mismatch": "The assumed identity did not match this AWS account and role.",
    "read_denied": "The role could not read account metadata in the selected region. Check its permissions and region availability.",
}


@router.post("/{org_id}/connections/{account_id}/verify", response_model=Connection)
def verify(
    org_id: OrgId, account_id: AccountId, body: VerifyConnection,
    user: Principal, store: Organizations, verifier: Verifier,
) -> dict[str, Any]:
    require_manager(store, user, org_id)
    account = store.connection(org_id, account_id)
    if not account:
        raise HTTPException(404, "Connection not found.")
    if body.role_arn != account["role_arn"]:
        raise HTTPException(422, "Enter the exact role ARN produced by this connection’s CloudFormation stack.")
    allowed = os.environ.get("VERIFICATION_ALLOWED_ACCOUNTS", "")
    if allowed and account_id not in allowed.split(","):
        raise HTTPException(403, "This AWS account is outside the approved beta scope.")
    try:
        attempt = store.begin_verification(account, user)
    except VerificationBusy:
        raise HTTPException(429, "Wait 30 seconds before trying verification again.", headers={"Retry-After": "30"}) from None
    result = verifier(account, attempt)
    if result == "connection_changed":
        raise HTTPException(409, "The connection changed. Reload and try again.")
    if result != "verified" and result not in VERIFICATION_ERRORS:
        raise HTTPException(503, "AWS verification is temporarily unavailable. Try again shortly.")
    try:
        updated = store.finish_verification(account, user, attempt, "verified" if result == "verified" else "failed")
    except ConnectionChanged:
        raise HTTPException(409, "The connection or your access changed. Reload and try again.") from None
    if result != "verified":
        raise HTTPException(422, VERIFICATION_ERRORS[result])
    return updated

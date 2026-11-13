"""Verify the exact generated role using bounded, read-only AWS calls."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from scanner.findings import format_timestamp
from scanner.organizations import MANAGE_ACCOUNTS, OrganizationStore
from scanner.session import ROLE_SESSION_NAME

VERIFY_CONFIG = Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1})
REGIONS = ("us-east-1", "us-east-2", "us-west-2", "eu-west-1", "eu-west-2")
DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
VERIFICATION_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": ["sts:GetCallerIdentity", "iam:GetAccountSummary", "ec2:DescribeRegions"],
        "Resource": "*",
    }],
})


def _denied(error: ClientError) -> bool:
    return error.response["Error"]["Code"] in DENIED


def verify_role(base: boto3.Session, account: dict[str, Any]) -> str:
    account_id, role_arn, region = (account[key] for key in ("aws_account_id", "role_arn", "region"))
    match = re.fullmatch(r"arn:aws:iam::([0-9]{12}):role/(PillarscanAuditRole-[0-9a-f]{16})", role_arn)
    if not match or match[1] != account_id or region not in REGIONS:
        return "identity_mismatch"

    sts = base.client("sts", region_name=region, config=VERIFY_CONFIG)
    params = {
        "RoleArn": role_arn,
        "RoleSessionName": ROLE_SESSION_NAME,
        "DurationSeconds": 900,
        "Policy": VERIFICATION_POLICY,
    }
    try:
        credentials = sts.assume_role(**params, ExternalId=account["external_id"])["Credentials"]
    except ClientError as error:
        return "assume_denied" if _denied(error) else "unavailable"
    except BotoCoreError:
        return "unavailable"

    try:
        for external_id in ({}, {"ExternalId": "pillarscan-verification-invalid"}):
            try:
                sts.assume_role(**params, **external_id)
            except ClientError as error:
                if not _denied(error):
                    return "unavailable"
            else:
                return "external_id_not_required"

        assumed = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )
        identity = assumed.client("sts", config=VERIFY_CONFIG).get_caller_identity()
        expected = f"arn:aws:sts::{account_id}:assumed-role/{match[2]}/{ROLE_SESSION_NAME}"
        if identity["Account"] != account_id or identity["Arn"] != expected:
            return "identity_mismatch"
        assumed.client("iam", config=VERIFY_CONFIG).get_account_summary()
        assumed.client("ec2", config=VERIFY_CONFIG).describe_regions(RegionNames=[region])
    except ClientError as error:
        return "read_denied" if _denied(error) else "unavailable"
    except BotoCoreError:
        return "unavailable"
    return "verified"


def verify_connection(
    store: OrganizationStore, organization_id: str, account_id: str, connection_id: str, attempt: str
) -> str:
    account = store.connection(organization_id, account_id)
    now = format_timestamp(datetime.now(timezone.utc))
    if (
        not account
        or account["account_connection_id"] != connection_id
        or account.get("verification_attempt") != attempt
        or account.get("verification_until", "") <= now
        or store.role(account.get("verification_actor", ""), organization_id) not in MANAGE_ACCOUNTS
    ):
        return "connection_changed"
    return verify_role(boto3.Session(), account)

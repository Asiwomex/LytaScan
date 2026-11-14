"""Scanner Lambda: run the scans requested on the queue and store them.

There are two kinds of request:

    {}                                        scan the platform's own account
                                              and store it scrubbed, for the
                                              public dashboard
    {"user_id": ..., "aws_account_id": ...}   scan an account a signed-in
                                              user connected, and store it
                                              for that user only

Either way the function's own role can do almost nothing in AWS. It assumes
a read-only audit role in the account to scan and uses that.

A role that cannot be assumed is not an error in the scanner. It usually
means someone removed LytaScan from that account, which they are free to
do, so the request is logged and dropped. Raising would put the message
back on the queue, send it to the dead-letter queue and fire the error
alarm every day for something nobody needs to fix.

Environment:
    TABLE_NAME             DynamoDB table for scans and connected accounts
    AUDIT_ROLE_ARN         audit role in the platform's own account
    EXTERNAL_ID_PARAMETER  SSM parameter holding that role's external ID
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

from scanner.accounts import AccountStore, tenant_key
from scanner.engine import run_scan
from scanner import deletion_inventory
from scanner.lifecycle import FindingStore, fingerprint
from scanner.scrub import scrub
from scanner.session import assume_role_session
from scanner.store import ScanStore
from scanner.organizations import OrganizationStore
from scanner.org_jobs import OrgJobs, run_job
from scanner.scan_progress import job_checks
from scanner.verification import verify_connection

logger = logging.getLogger()
logger.setLevel(logging.INFO)

COULD_NOT_ASSUME = (
    "LytaScan could not assume the role in this account. Check that the "
    "CloudFormation stack finished creating and was made from the link on "
    "this page."
)
WRONG_ACCOUNT = "The role belongs to a different AWS account from the one entered."

# What AWS answers when the role, or the parameter holding its external ID,
# no longer exists or no longer trusts the scanner.
ROLE_GONE = {"AccessDenied", "NoSuchEntity", "ParameterNotFound"}


def _own_external_id() -> str:
    # Read at run time rather than kept in an environment variable, where
    # anyone who can view the function's configuration could read it.
    parameter = boto3.client("ssm").get_parameter(
        Name=os.environ["EXTERNAL_ID_PARAMETER"], WithDecryption=True
    )
    value: str = parameter["Parameter"]["Value"]
    return value


def scan_own_account() -> dict[str, Any]:
    try:
        session = assume_role_session(
            boto3.Session(), os.environ["AUDIT_ROLE_ARN"], _own_external_id()
        )
    except ClientError as error:
        code = error.response["Error"]["Code"]
        if code not in ROLE_GONE:
            raise
        logger.warning(
            "skipping the public scan: the platform's audit role cannot be used (%s)", code
        )
        return {"skipped": "public", "reason": code}
    # The API serves these scans without sign-in, so the account ID, user
    # names and resource IDs are replaced before anything is stored.
    report = scrub(run_scan(session).to_dict())
    scan_id = ScanStore.from_env().put_scan(report)
    logger.info("stored public scan %s with %d findings", scan_id, len(report["findings"]))
    return {"scan_id": scan_id, "findings": len(report["findings"])}


def scan_connected_account(user_id: str, aws_account_id: str) -> dict[str, Any]:
    accounts = AccountStore.from_env()
    account = accounts.get(user_id, aws_account_id)
    if account is None:
        # The account was removed after the scan was requested.
        logger.warning("no connected account %s for this user", aws_account_id)
        return {"skipped": aws_account_id}

    try:
        session = assume_role_session(
            boto3.Session(), account["role_arn"], account["external_id"]
        )
    except ClientError as error:
        # Retrying will not help: the role is missing or does not trust us.
        # Record why, so the user sees it, and let the message go.
        logger.warning("cannot assume role: %s", error.response["Error"]["Code"])
        accounts.record_failure(user_id, aws_account_id, COULD_NOT_ASSUME)
        return {"failed": aws_account_id}

    report = run_scan(session).to_dict()
    if report["scan"]["account_id"] != aws_account_id:
        accounts.record_failure(user_id, aws_account_id, WRONG_ACCOUNT)
        return {"failed": aws_account_id}

    scan_id = ScanStore.from_env().put_scan(report, owner=tenant_key(user_id, aws_account_id))
    accounts.record_scan(user_id, aws_account_id, scan_id)
    logger.info("stored private scan %s with %d findings", scan_id, len(report["findings"]))
    return {"scan_id": scan_id, "findings": len(report["findings"])}


def handler(event: dict[str, Any], context: object) -> dict[str, Any]:
    if event.get("operation") == "verify_connection":
        store = OrganizationStore(boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"]))
        return {"result": verify_connection(
            store, event["organization_id"], event["aws_account_id"],
            event["account_connection_id"], event["verification_attempt"],
        )}
    requests = [json.loads(record["body"] or "{}") for record in event.get("Records", [])]
    results: list[dict[str, Any]] = []
    scanned_own_account = False
    # An event with no records (a manual test invoke) means one public scan.
    for request in requests or [{}]:
        if request.get("operation") == "org_cleanup":
            store = OrgJobs(boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"]))
            store.purge_connection(request["organization_id"], request["generation"])
        elif request.get("operation") == "org_scan":
            store = OrgJobs(boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"]))
            run_job(store, request["organization_id"], request["job_id"], scan_organization_account, supports_progress=True)
        elif "user_id" in request:
            results.append(
                scan_connected_account(request["user_id"], request["aws_account_id"])
            )
        elif not scanned_own_account:
            # Two public requests close together should not produce two
            # identical scans.
            scanned_own_account = True
            results.append(scan_own_account())
    # If anything above raises, the message goes back on the queue and, after
    # a second failure, to the dead-letter queue.
    return {"scans": results}


def scan_organization_account(connection: dict[str, Any], region: str, *, verification=None, progress=None) -> dict[str, Any]:
    allowed = os.environ.get("VERIFICATION_ALLOWED_ACCOUNTS", "")
    if allowed and connection["aws_account_id"] not in allowed.split(","):
        raise ValueError("Account outside approved scope")
    session = assume_role_session(boto3.Session(region_name=region), connection["role_arn"], connection["external_id"])
    if session.client("sts").get_caller_identity()["Account"] != connection["aws_account_id"]:
        raise ValueError("Unexpected AWS account")
    checks = job_checks(verification)
    if not checks:
        raise ValueError("Requested scan checks are unavailable")
    report = run_scan(session, regions=[region], checks=checks, version=2, progress=progress, evaluation_filter=(
        None if not verification or not verification.get("finding_id") else lambda item: fingerprint(
            connection["organization_id"], connection["account_connection_id"], item.to_dict()
        ) == verification["finding_id"]
    )).to_dict()
    if not verification:
        options = {}
        if progress is not None:
            progress.flush()
            options["should_continue"] = progress.probe
            options["resource_types"] = FindingStore(progress.store.table).inventory_types(
                connection["organization_id"], connection["account_connection_id"],
            )
        report["inventory"] = deletion_inventory.collect_inventory(session, report["scan"]["account_id"], region, **options)
    return report

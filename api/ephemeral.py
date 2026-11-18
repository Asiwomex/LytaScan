"""Request-scoped read-only scans using a visitor's temporary AWS role credentials.

No profiles, cookies, database records, credential caches, or background workers
are used. Each request owns its explicit boto3 session and releases it on return.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from itertools import islice
from time import monotonic
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from botocore.session import Session as BotocoreSession

from scanner.check import CheckContext, Scope
from scanner.engine import discover_checks, scope_outcome, scope_plan
from scanner.findings import Status, format_timestamp
from scanner.registry import REGISTRY_VERSION, catalog

MAX_BODY_BYTES = 16_384
MAX_REGIONS = 6
MAX_FINDINGS = 2_000
MAX_AWS_REQUESTS = 300
SCOPE_SECONDS = 210
REGIONS = tuple(sorted(BotocoreSession().get_available_regions("ec2", partition_name="aws")))
CLIENT_CONFIG = Config(connect_timeout=5, read_timeout=10,
                       retries={"mode": "standard", "total_max_attempts": 2})


class ScanRequestError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class ScopeBudgetExceeded(Exception):
    pass


class ReadOnlyOperationRequired(Exception):
    pass


class _Budget:
    def __init__(self):
        self.deadline = monotonic() + SCOPE_SECONDS
        self.calls = 0

    def before_call(self, model, **_kwargs):
        operation = model.name
        service = model.service_model.service_name
        allowed = operation == "GetCallerIdentity" if service == "sts" else operation.startswith(
            ("Get", "List", "Describe", "BatchGet")
        )
        if not allowed:
            raise ReadOnlyOperationRequired()
        self.calls += 1
        if self.calls > MAX_AWS_REQUESTS or monotonic() >= self.deadline:
            raise ScopeBudgetExceeded()


class _VisitorSession(boto3.Session):
    """Override scanner client defaults without modifying shared scanner state."""
    def __init__(self, credentials: dict[str, str], region: str):
        super().__init__(aws_access_key_id=credentials["access_key_id"],
                         aws_secret_access_key=credentials["secret_access_key"],
                         aws_session_token=credentials["session_token"], region_name=region)
        self._budget = _Budget()
        self._clients = []

    def client(self, service_name, *args, **kwargs):
        # Scanner contexts ordinarily supply their longer-running Lambda config.
        kwargs["config"] = CLIENT_CONFIG
        client = super().client(service_name, *args, **kwargs)
        client.meta.events.register("before-call.*.*", self._budget.before_call)
        self._clients.append(client)
        return client

    def close(self):
        for client in self._clients:
            client.close()
        self._clients.clear()


def public_info() -> dict[str, Any]:
    return {"service": "LytaScan session scanner", "registry_version": REGISTRY_VERSION,
            "checks": list(catalog()), "regions": list(REGIONS),
            "email_delivery": _email_configured()}


def _email_configured() -> bool:
    return (len(os.environ.get("SESSION_REPORT_SECRET", "")) >= 32
            and bool(os.environ.get("RESEND_API_KEY"))
            and bool(os.environ.get("REPORT_FROM_EMAIL")))


def _report_email(value: Any) -> str | None:
    if value is None or value == "":
        return None
    if (not isinstance(value, str) or len(value) > 254 or not re.fullmatch(
            r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}", value)):
        raise ScanRequestError("invalid_report_email", "Enter a valid email address for the report.")
    return value.lower()


def _email_token(account_id: str, email: str | None) -> str | None:
    if not email or not _email_configured():
        return None
    details = {"account_id": account_id, "email": email,
               "expires_at": int(datetime.now(timezone.utc).timestamp()) + 3600,
               "nonce": uuid4().hex}
    payload = base64.urlsafe_b64encode(json.dumps(details, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(os.environ["SESSION_REPORT_SECRET"].encode(), payload.encode(), hashlib.sha256).digest()
    return payload + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")


def _credentials(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"access_key_id", "secret_access_key", "session_token"}:
        raise ScanRequestError("temporary_credentials_required", "Provide all three temporary AWS role credential fields.")
    if not all(isinstance(item, str) for item in value.values()):
        raise ScanRequestError("temporary_credentials_required", "Provide all three temporary AWS role credential fields.")
    credentials = {key: item.strip() for key, item in value.items()}
    if not re.fullmatch(r"ASIA[A-Z0-9]{16}", credentials["access_key_id"]):
        raise ScanRequestError("temporary_credentials_required", "Use a temporary AWS access key beginning with ASIA, together with its session token.")
    if not re.fullmatch(r"[A-Za-z0-9/+=]{40}", credentials["secret_access_key"]):
        raise ScanRequestError("invalid_credentials", "Check the temporary AWS secret access key.")
    token = credentials["session_token"]
    if not 16 <= len(token) <= 12_000 or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise ScanRequestError("invalid_credentials", "Check the temporary AWS session token.")
    return credentials


def _regions(value: Any) -> list[str]:
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_REGIONS
            or any(not isinstance(item, str) or item not in REGIONS for item in value)
            or len(set(value)) != len(value)):
        raise ScanRequestError("invalid_regions", "Choose between one and six supported AWS regions, without duplicates.")
    return value


def _identity(session: boto3.Session) -> dict[str, str]:
    identity = session.client("sts", region_name=session.region_name).get_caller_identity()
    account = identity.get("Account", "")
    principal = identity.get("Arn", "")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        raise ScanRequestError("invalid_identity", "AWS did not return a valid account identity.", 401)
    if not isinstance(principal, str) or not re.fullmatch(
        rf"arn:aws:sts::{account}:assumed-role/[^\s]+/[^/\s]+", principal
    ):
        raise ScanRequestError("temporary_role_required", "Use temporary credentials from an AWS role with read-only audit access.", 401)
    return {"account_id": account, "principal_arn": principal}


def _aws_error(error: Exception) -> ScanRequestError:
    code = error.response.get("Error", {}).get("Code", "") if isinstance(error, ClientError) else ""
    if code in {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "InvalidToken", "SignatureDoesNotMatch", "UnrecognizedClientException"}:
        return ScanRequestError("credentials_expired_or_invalid", "AWS rejected these temporary credentials. Copy a fresh role session and reconnect.", 401)
    if "denied" in code.lower() or code == "UnauthorizedOperation":
        return ScanRequestError("access_denied", "AWS denied this request. Check the read-only role permissions.", 403)
    return ScanRequestError("aws_unavailable", "AWS could not complete this request. Retry with a fresh role session if needed.", 502)


def scan_action(payload: Any) -> dict[str, Any]:
    """Execute one action. Validating a request never uses operator credentials."""
    if (not isinstance(payload, dict) or not isinstance(payload.get("action"), str)
            or payload["action"] not in {"inspect", "evaluate"}):
        raise ScanRequestError("invalid_action", "Choose a supported scan action.")
    report_email = _report_email(payload.get("report_email")) if payload["action"] == "inspect" else None
    regions = _regions(payload.get("regions"))
    credentials = _credentials(payload.get("credentials"))
    checks = discover_checks(include_v2=True)
    chosen = None
    region = None
    if payload["action"] == "evaluate":
        chosen = next((check for check in checks if check.meta.check_id == payload.get("check_id")), None)
        region = payload.get("region")
        if chosen is None or not isinstance(region, str):
            raise ScanRequestError("invalid_scope", "Choose a check from the current scan catalog.")
        if (chosen.meta.scope is Scope.GLOBAL and region != "global") or (
            chosen.meta.scope is Scope.REGIONAL and region not in regions
        ):
            raise ScanRequestError("invalid_scope", "The check region does not match the selected scan scope.")
    session = _VisitorSession(credentials, regions[0])
    try:
        identity = _identity(session)
        if payload.get("account_id") is not None and payload["account_id"] != identity["account_id"]:
            raise ScanRequestError("identity_changed", "The AWS identity changed. Disconnect and reconnect before scanning.", 409)
        if payload["action"] == "inspect":
            return {**identity, "regions": regions, "registry_version": REGISTRY_VERSION,
                    "checks": list(catalog()), "scopes": scope_plan(checks, regions),
                    "email_token": _email_token(identity["account_id"], report_email)}
        started_at = datetime.now(timezone.utc)
        ctx = CheckContext(session=session, account_id=identity["account_id"], region=region,
                           now=started_at, safe_errors=True)
        findings = []
        iterator = None
        try:
            iterator = iter(chosen.run(ctx))
            for finding in islice(iterator, MAX_FINDINGS + 1):
                findings.append(finding)
            if len(findings) > MAX_FINDINGS:
                findings = findings[:MAX_FINDINGS]
                findings.append(ctx.finding(chosen.meta, Status.UNKNOWN, ctx.account_arn,
                                "This scope exceeded the report result limit and is incomplete.", reason_code="result_limit"))
        except ScopeBudgetExceeded:
            findings.append(ctx.finding(chosen.meta, Status.UNKNOWN, ctx.account_arn,
                            "This scope reached the request budget and is incomplete.", reason_code="request_budget_exceeded"))
        except Exception as error:
            # CheckContext's safe error mapping never includes AWS response text.
            findings.append(ctx.error(chosen.meta, ctx.account_arn, error))
        finally:
            if iterator is not None and hasattr(iterator, "close"):
                iterator.close()
        return {"account_id": identity["account_id"], "check_id": chosen.meta.check_id, "region": region,
                "scope": scope_outcome(chosen, region, findings),
                "findings": [finding.to_dict() for finding in findings],
                "started_at": format_timestamp(started_at),
                "finished_at": format_timestamp(datetime.now(timezone.utc))}
    except ScanRequestError:
        raise
    except (ClientError, BotoCoreError) as error:
        raise _aws_error(error) from None
    finally:
        # The request has no module-level session/client cache or persistent store.
        credentials.clear()
        session.close()
        session = None


def same_origin(origin: str | None, host: str | None) -> bool:
    if not origin or not host:
        return False
    try:
        parsed = urlsplit(origin)
        return (parsed.scheme == "https" and parsed.netloc.lower() == host.lower()
                and not parsed.path and not parsed.query and not parsed.fragment
                and parsed.username is None and parsed.password is None)
    except ValueError:
        return False


def request_json(body: bytes, origin: str | None, host: str | None,
                 content_type: str | None) -> tuple[int, dict[str, Any]]:
    """HTTP boundary shared by Vercel and unit tests, with redacted failures."""
    try:
        if not same_origin(origin, host):
            raise ScanRequestError("origin_denied", "Open the scan runner on the LytaScan site to connect.", 403)
        if not content_type or content_type.split(";", 1)[0].strip().lower() != "application/json":
            raise ScanRequestError("json_required", "Send this request as JSON.", 415)
        if len(body) > MAX_BODY_BYTES:
            raise ScanRequestError("request_too_large", "The connection request is too large.", 413)
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise ScanRequestError("invalid_json", "The connection request could not be read.") from None
        return 200, scan_action(payload)
    except ScanRequestError as error:
        return error.status, {"error": {"code": error.code, "message": error.message}}
    except Exception:
        # Never include an exception repr, request payload, or AWS credentials.
        return 500, {"error": {"code": "scan_unavailable", "message": "The scan request could not finish. Please retry."}}

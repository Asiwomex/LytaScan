"""In-process session-runner tests. All AWS responses are explicit Stubber fakes."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from api import ephemeral
from scanner.check import CheckMeta, Scope
from scanner.engine import Check
from scanner.findings import Pillar, Severity, Status

ORIGIN = "https://lytascan.lytaworks.com"
HOST = "lytascan.lytaworks.com"


@pytest.fixture
def credentials():
    return {"access_key_id": "ASIA" + "A" * 16, "secret_access_key": "b" * 40, "session_token": "c" * 200}


@pytest.fixture(autouse=True)
def stub_clients(monkeypatch):
    original = ephemeral._VisitorSession.client
    def client(self, service_name, *args, **kwargs):
        result = original(self, service_name, *args, **kwargs)
        stubber = Stubber(result)
        if service_name == "sts":
            stubber.add_response("get_caller_identity", {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/VisitorReadOnly/visitor-scan", "UserId": "FAKE:visitor-scan"})
        elif service_name == "iam":
            stubber.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 0}})
        else:
            pytest.fail("Unexpected AWS client requested; no network calls are allowed")
        stubber.activate()
        return result
    monkeypatch.setattr(ephemeral._VisitorSession, "client", client)


def request(credentials, action="inspect", **fields):
    payload = {"action": action, "credentials": credentials, "regions": ["us-east-1"], **fields}
    return ephemeral.request_json(json.dumps(payload).encode(), ORIGIN, HOST, "application/json")


def test_inspect_returns_verified_role_and_all_check_scopes(credentials):
    status, body = request(credentials)
    assert status == 200
    assert body["account_id"] == "123456789012"
    assert ":assumed-role/VisitorReadOnly/visitor-scan" in body["principal_arn"]
    assert len(body["checks"]) >= 60
    assert len(body["scopes"]) == len(body["checks"])
    assert len({check["primary_pillar"] for check in body["checks"]}) == 6
    assert body["email_token"] is None
    assert all(value not in json.dumps(body) for value in credentials.values())


def test_evaluate_runs_existing_check_with_canonical_findings(credentials):
    status, body = request(credentials, "evaluate", check_id="iam_root_mfa", region="global")
    assert status == 200
    assert body["scope"]["status"] == "complete"
    assert body["check_id"] == "iam_root_mfa"
    finding = body["findings"][0]
    assert finding["account_id"] == "123456789012"
    assert finding["status"] == "fail"
    assert {"check_id", "title", "status", "description", "remediation", "resource_arn", "scanned_at"} <= finding.keys()


@pytest.mark.parametrize("replacement", [
    {"access_key_id": "AKIA" + "A" * 16}, {"session_token": ""}, {"session_token": "contains spaces"},
    {"secret_access_key": "bad"}, {"access_key_id": 123},
])
def test_invalid_credentials_rejected_without_env_fallback(credentials, replacement, monkeypatch):
    credentials.update(replacement)
    monkeypatch.setattr(ephemeral, "_VisitorSession", lambda *_args: pytest.fail("must validate before creating a session"))
    status, body = request(credentials)
    assert status == 400
    assert body["error"]["code"] in {"temporary_credentials_required", "invalid_credentials"}
    assert "bad" not in json.dumps(body)


@pytest.mark.parametrize("regions", [[], ["http://evil.example"], ["us-east-1", "us-east-1"], ["fake-region-1"], "us-east-1"])
def test_invalid_regions_rejected_before_aws(credentials, regions, monkeypatch):
    monkeypatch.setattr(ephemeral, "_VisitorSession", lambda *_args: pytest.fail("must validate regions first"))
    status, body = request(credentials, regions=regions)
    assert status == 400
    assert body["error"]["code"] == "invalid_regions"


@pytest.mark.parametrize("check_id,region", [
    ("delete_everything", "us-east-1"), ("iam_root_mfa", "us-east-1"),
    ("ec2_imdsv2_required", "global"), ("ec2_security_group_open_admin_ports", "eu-west-1"),
])
def test_unknown_or_mismatched_scope_rejected(credentials, check_id, region, monkeypatch):
    monkeypatch.setattr(ephemeral, "_VisitorSession", lambda *_args: pytest.fail("must validate scopes first"))
    status, body = request(credentials, "evaluate", check_id=check_id, region=region)
    assert status == 400
    assert body["error"]["code"] == "invalid_scope"


def test_requests_use_explicit_visitor_credentials_not_operator_environment(credentials):
    session = ephemeral._VisitorSession(credentials, "us-east-1")
    try:
        frozen = session.get_credentials().get_frozen_credentials()
        assert frozen.access_key == credentials["access_key_id"]
        assert frozen.secret_key == credentials["secret_access_key"]
        assert frozen.token == credentials["session_token"]
        assert frozen.access_key != "testing"
    finally:
        session.close()


@pytest.mark.parametrize("service,operation", [("iam", "CreateUser"), ("s3", "DeleteBucket"), ("sts", "GetSessionToken")])
def test_runtime_guard_rejects_mutation_and_credential_issuance(service, operation):
    model = SimpleNamespace(name=operation, service_model=SimpleNamespace(service_name=service))
    with pytest.raises(ephemeral.ReadOnlyOperationRequired):
        ephemeral._Budget().before_call(model)


def test_runtime_guard_limits_request_count(monkeypatch):
    monkeypatch.setattr(ephemeral, "MAX_AWS_REQUESTS", 1)
    model = SimpleNamespace(name="GetCallerIdentity", service_model=SimpleNamespace(service_name="sts"))
    budget = ephemeral._Budget()
    budget.before_call(model)
    with pytest.raises(ephemeral.ScopeBudgetExceeded):
        budget.before_call(model)


def test_expired_credentials_never_expose_aws_message_or_secret(credentials, monkeypatch):
    secret = credentials["secret_access_key"]
    def reject(_session):
        raise ClientError({"Error": {"Code": "ExpiredToken", "Message": "leaked " + secret}}, "GetCallerIdentity")
    monkeypatch.setattr(ephemeral, "_identity", reject)
    status, body = request(credentials)
    assert status == 401
    assert body["error"]["code"] == "credentials_expired_or_invalid"
    assert secret not in json.dumps(body)
    assert "leaked" not in json.dumps(body)


def test_no_iam_user_or_root_session_accepted(credentials, monkeypatch):
    def client(self, _service_name, *args, **kwargs):
        return SimpleNamespace(get_caller_identity=lambda: {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:root"})
    monkeypatch.setattr(ephemeral._VisitorSession, "client", client)
    status, body = request(credentials)
    assert status == 401
    assert body["error"]["code"] == "temporary_role_required"


def test_account_switch_is_detected(credentials):
    status, body = request(credentials, account_id="999988887777")
    assert status == 409
    assert body["error"]["code"] == "identity_changed"


def test_permission_failure_is_incomplete_without_aws_error_text(credentials, monkeypatch):
    meta = CheckMeta("test_read", "A test read", Pillar.SECURITY, Severity.HIGH, "AWS::IAM::Account", Scope.GLOBAL, "Review permissions")
    def denied(_ctx):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": credentials["session_token"]}}, "GetAccountSummary")
    monkeypatch.setattr(ephemeral, "discover_checks", lambda **_kwargs: [Check(meta=meta, run=denied)])
    status, body = request(credentials, "evaluate", check_id="test_read", region="global")
    assert status == 200
    assert body["scope"]["status"] == "incomplete"
    assert body["scope"]["reason_codes"] == ["permission_denied"]
    assert credentials["session_token"] not in json.dumps(body)


def test_budget_failure_preserves_completed_findings_and_marks_scope_incomplete(credentials, monkeypatch):
    meta = CheckMeta("test_budget", "A budgeted read", Pillar.SECURITY, Severity.HIGH, "AWS::IAM::Account", Scope.GLOBAL, "Reduce scope")
    def exhausted(ctx):
        yield ctx.finding(meta, Status.PASS, ctx.account_arn, "A completed read")
        raise ephemeral.ScopeBudgetExceeded()
    monkeypatch.setattr(ephemeral, "discover_checks", lambda **_kwargs: [Check(meta=meta, run=exhausted)])
    status, body = request(credentials, "evaluate", check_id="test_budget", region="global")
    assert status == 200
    assert body["scope"]["status"] == "incomplete"
    assert [item["status"] for item in body["findings"]] == ["pass", "unknown"]
    assert body["findings"][-1]["reason_code"] == "request_budget_exceeded"


def test_result_limit_never_reports_complete_scope(credentials, monkeypatch):
    monkeypatch.setattr(ephemeral, "MAX_FINDINGS", 2)
    meta = CheckMeta("test_limit", "A bounded read", Pillar.SECURITY, Severity.HIGH, "AWS::IAM::Account", Scope.GLOBAL, "Reduce scope")
    def many(ctx):
        for number in range(8):
            yield ctx.finding(meta, Status.PASS, ctx.account_arn, f"Read {number}")
    monkeypatch.setattr(ephemeral, "discover_checks", lambda **_kwargs: [Check(meta=meta, run=many)])
    status, body = request(credentials, "evaluate", check_id="test_limit", region="global")
    assert status == 200
    assert len(body["findings"]) == 3
    assert body["scope"]["status"] == "incomplete"
    assert body["findings"][-1]["reason_code"] == "result_limit"


@pytest.mark.parametrize("origin,host", [(None, HOST), ("https://attacker.example", HOST), (ORIGIN + "/path", HOST), ("http://" + HOST, HOST), (ORIGIN, "attacker.example")])
def test_origin_is_required_and_must_match(origin, host):
    status, body = ephemeral.request_json(b"{}", origin, host, "application/json")
    assert status == 403
    assert body["error"]["code"] == "origin_denied"


def test_http_boundary_rejects_bad_content_type_and_oversized_body():
    assert ephemeral.request_json(b"{}", ORIGIN, HOST, "text/plain")[0] == 415
    assert ephemeral.request_json(b"x" * (ephemeral.MAX_BODY_BYTES + 1), ORIGIN, HOST, "application/json")[0] == 413
    assert ephemeral.request_json(b"not json", ORIGIN, HOST, "application/json")[0] == 400


def test_unexpected_failure_redacts_everything(credentials, monkeypatch):
    def broken(*_args):
        raise RuntimeError(str(credentials))
    monkeypatch.setattr(ephemeral, "scan_action", broken)
    status, body = request(credentials)
    assert status == 500
    assert all(value not in json.dumps(body) for value in credentials.values())


def test_public_health_has_no_aws_calls(monkeypatch):
    monkeypatch.setattr(ephemeral, "_VisitorSession", lambda *_args: pytest.fail("health must not call AWS"))
    body = ephemeral.public_info()
    assert len(body["checks"]) >= 60
    assert "us-east-1" in body["regions"]
    assert "credentials" not in body


def test_email_authorization_is_bound_to_verified_account_and_recipient(credentials, monkeypatch):
    secret = "report-secret-" + "s" * 32
    monkeypatch.setenv("SESSION_REPORT_SECRET", secret)
    monkeypatch.setenv("RESEND_API_KEY", "provider-key-not-in-output")
    monkeypatch.setenv("REPORT_FROM_EMAIL", "reports@example.test")
    status, body = request(credentials, report_email="recipient@example.test")
    assert status == 200
    encoded, signature = body["email_token"].split(".")
    expected = base64.urlsafe_b64encode(hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()).decode().rstrip("=")
    assert hmac.compare_digest(expected, signature)
    details = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    assert set(details) == {"account_id", "email", "expires_at", "nonce"}
    assert details["account_id"] == "123456789012"
    assert details["email"] == "recipient@example.test"
    assert len(details["nonce"]) == 32
    assert all(value not in json.dumps(body) for value in credentials.values())
    assert secret not in json.dumps(body)


def test_email_token_is_not_issued_without_email_service(credentials):
    status, body = request(credentials, report_email="recipient@example.test")
    assert status == 200
    assert body["email_token"] is None


def test_invalid_email_rejected_without_auth_request(credentials, monkeypatch):
    monkeypatch.setattr(ephemeral, "_VisitorSession", lambda *_args: pytest.fail("email validation must happen first"))
    status, body = request(credentials, report_email="bad\nBcc:someone@example.test")
    assert status == 400
    assert body["error"]["code"] == "invalid_report_email"


@pytest.mark.parametrize("action", [None, [], {}, True, 123, "unsupported"])
def test_malformed_action_is_a_client_error(action):
    status, body = ephemeral.request_json(json.dumps({"action": action}).encode(), ORIGIN, HOST, "application/json")
    assert status == 400
    assert body["error"]["code"] == "invalid_action"


def _adapter_handler(monkeypatch, body=b"{}", content_length="2"):
    import importlib.util
    import io
    from email.message import Message
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("session_scan_adapter_test", Path(__file__).resolve().parents[2] / "web" / "api" / "scan.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    endpoint = module.handler.__new__(module.handler)
    endpoint.headers = Message()
    endpoint.headers["Origin"] = ORIGIN
    endpoint.headers["Host"] = HOST
    endpoint.headers["Content-Type"] = "application/json"
    if content_length is not None:
        endpoint.headers["Content-Length"] = content_length
    endpoint.rfile = io.BytesIO(body)
    endpoint.wfile = io.BytesIO()
    output = {"headers": {}}
    endpoint.send_response = lambda status: output.update(status=status)
    endpoint.send_header = lambda name, value: output["headers"].update({name: value})
    endpoint.end_headers = lambda: None
    return module, endpoint, output


def test_http_adapter_reads_bounded_body_and_sets_private_headers(monkeypatch):
    module, endpoint, output = _adapter_handler(monkeypatch)
    received = []
    def fake_request(body, origin, host, content_type):
        received.append((body, origin, host, content_type))
        return 400, {"error": {"code": "invalid_action", "message": "Choose a scan action."}}
    monkeypatch.setattr(module, "request_json", fake_request)
    endpoint.do_POST()
    assert received == [(b"{}", ORIGIN, HOST, "application/json")]
    assert output["status"] == 400
    assert output["headers"]["Cache-Control"] == "no-store, private, max-age=0"
    assert output["headers"]["X-Content-Type-Options"] == "nosniff"
    assert "Access-Control-Allow-Origin" not in output["headers"]
    assert json.loads(endpoint.wfile.getvalue())["error"]["code"] == "invalid_action"


@pytest.mark.parametrize("length", [None, "invalid", "-1", str(ephemeral.MAX_BODY_BYTES + 1)])
def test_http_adapter_rejects_bad_lengths_without_reading_body(monkeypatch, length):
    module, endpoint, output = _adapter_handler(monkeypatch, content_length=length)
    monkeypatch.setattr(module, "request_json", lambda *_args: pytest.fail("oversized bodies must not be processed"))
    endpoint.do_POST()
    assert output["status"] == 413
    assert endpoint.rfile.tell() == 0


def test_http_adapter_health_and_options_do_not_touch_aws(monkeypatch):
    module, endpoint, output = _adapter_handler(monkeypatch)
    monkeypatch.setattr(module, "public_info", lambda: {"service": "LytaScan session scanner"})
    endpoint.do_GET()
    assert output["status"] == 200
    assert json.loads(endpoint.wfile.getvalue())["service"] == "LytaScan session scanner"
    endpoint.do_OPTIONS()
    assert output["status"] == 405


def test_report_email_is_normalized_for_delivery_token():
    assert ephemeral._report_email("Recipient@Example.TEST") == "recipient@example.test"

from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.verification import verify_connection, verify_role

ACCOUNT = {
    "aws_account_id": "111122223333",
    "role_arn": "arn:aws:iam::111122223333:role/PillarscanAuditRole-0123456789abcdef",
    "external_id": "expected-connection-id",
    "region": "us-east-1",
}
IDENTITY = {
    "Account": ACCOUNT["aws_account_id"],
    "Arn": "arn:aws:sts::111122223333:assumed-role/PillarscanAuditRole-0123456789abcdef/pillarscan-scan",
}
CREDS = {"Credentials": {"AccessKeyId": "temporary", "SecretAccessKey": "temporary", "SessionToken": "temporary"}}


def denied():
    return ClientError({"Error": {"Code": "AccessDenied"}}, "AssumeRole")


@pytest.mark.parametrize(("responses", "identity", "blocked", "expected"), [
    ([CREDS, denied(), denied()], IDENTITY, False, "verified"),
    ([denied()], IDENTITY, False, "assume_denied"),
    ([CREDS, CREDS], IDENTITY, False, "external_id_not_required"),
    ([CREDS, denied(), CREDS], IDENTITY, False, "external_id_not_required"),
    ([CREDS, denied(), denied()], {**IDENTITY, "Account": "000000000000"}, False, "identity_mismatch"),
    ([CREDS, denied(), denied()], IDENTITY, True, "read_denied"),
])
def test_verify_role(monkeypatch, responses, identity, blocked, expected):
    base = Mock()
    sts = base.client.return_value
    sts.assume_role.side_effect = responses
    clients = {service: Mock() for service in ("sts", "iam", "ec2")}
    clients["sts"].get_caller_identity.return_value = identity
    if blocked:
        clients["iam"].get_account_summary.side_effect = denied()
    assumed = Mock()
    assumed.client.side_effect = lambda service, **_: clients[service]
    monkeypatch.setattr("scanner.verification.boto3.Session", lambda **_: assumed)
    assert verify_role(base, ACCOUNT) == expected
    assert sts.assume_role.call_args_list[0].kwargs["ExternalId"] == ACCOUNT["external_id"]
    if len(responses) > 1:
        assert "ExternalId" not in sts.assume_role.call_args_list[1].kwargs
    if expected == "verified":
        clients["ec2"].describe_regions.assert_called_once_with(RegionNames=["us-east-1"])


def test_rejects_role_outside_connection_before_aws_call():
    base = Mock()
    assert verify_role(base, {**ACCOUNT, "role_arn": ACCOUNT["role_arn"].replace("arn:aws:", "arn:aws-cn:")}) == "identity_mismatch"
    base.client.assert_not_called()


def test_worker_skips_stale_or_unauthorized_verification(monkeypatch):
    store = Mock()
    store.connection.return_value = {
        **ACCOUNT, "account_connection_id": "generation", "verification_attempt": "current",
        "verification_until": "9999-01-01T00:00:00Z", "verification_actor": "owner",
    }
    store.role.return_value = None
    session = Mock()
    monkeypatch.setattr("scanner.verification.boto3.Session", session)
    assert verify_connection(store, "org", ACCOUNT["aws_account_id"], "generation", "old") == "connection_changed"
    assert verify_connection(store, "org", ACCOUNT["aws_account_id"], "generation", "current") == "connection_changed"
    session.assert_not_called()

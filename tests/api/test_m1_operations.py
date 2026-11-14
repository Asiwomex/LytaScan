from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from api.app import app
from api.connection_cleanup import clean_now, get_cleanup_dispatcher
from api.onboarding import get_organizations, principal
from api.org_jobs import get_dispatcher
from api.team import verified_email
from scanner.accounts import AccountStore, tenant_key
from scanner.findings import format_timestamp
from scanner.org_jobs import OrgJobs, run_job
from scanner.organizations import OrganizationStore, connection_key, membership_key
from scanner.organizations import org_key
from scanner.store import ScanStore

ACCOUNT = "111122223333"
OWNER = {"test-subject": "owner"}


@pytest.fixture
def workspace(table):
    store = OrganizationStore(table)
    messages = []
    app.dependency_overrides.update({
        verified_email: lambda: "invitee@example.test",
        get_organizations: lambda: store,
        get_dispatcher: lambda: lambda *args: messages.append(args),
        get_cleanup_dispatcher: lambda: clean_now,
    })

    def subject(request: Request):
        return request.headers.get("test-subject", "unrelated")

    app.dependency_overrides[principal] = subject
    org = store.create("owner", "Northwind", uuid4().hex)["organization_id"]
    connection = store.connect("owner", org, ACCOUNT, "Sandbox", "us-east-1")
    table.update_item(Key=connection_key(org, ACCOUNT), UpdateExpression="SET #status = :verified",
                      ExpressionAttributeNames={"#status": "status"}, ExpressionAttributeValues={":verified": "verified"})
    try:
        yield TestClient(app), table, org, connection, messages
    finally:
        app.dependency_overrides.clear()


def sample_report():
    timestamp = format_timestamp(datetime.now(timezone.utc))
    return {"scan": {"account_id": ACCOUNT, "started_at": timestamp, "finished_at": timestamp,
                     "regions": ["us-east-1"], "checks_run": []}, "findings": []}


def test_scoped_invite_can_be_accepted_once_by_verified_recipient(workspace):
    client, table, org, connection, _ = workspace
    path = f"/v1/orgs/{org}/invites"
    response = client.post(path, headers=OWNER, json={
        "email": "invitee@example.test", "role": "viewer", "allowed_account": connection["account_connection_id"],
    })
    assert response.status_code == 201, response.text
    token = response.json()["token"]
    assert "token" not in client.get(path, headers=OWNER).json()[0]
    accept = "/v1/orgs/invites/accept"
    app.dependency_overrides[verified_email] = lambda: "wrong@example.test"
    assert client.post(accept, json={"token": token}).status_code == 409
    app.dependency_overrides[verified_email] = lambda: "invitee@example.test"
    assert client.post(accept, json={"token": token}).status_code == 200
    assert client.post(accept, json={"token": token}).status_code == 409
    assert table.get_item(Key=membership_key("unrelated", org))["Item"]["allowed_account"] == connection["account_connection_id"]
    assert client.post(path, json={"email": "other@example.test", "role": "administrator"}).status_code == 403


def test_revoked_invite_rejected(workspace):
    client, _, org, _, _ = workspace
    path = f"/v1/orgs/{org}/invites"
    invite = client.post(path, headers=OWNER, json={"email": "invitee@example.test", "role": "administrator"}).json()
    assert client.post(f"{path}/revoke", headers=OWNER, json={"invite_id": invite["invite_id"]}).status_code == 200
    assert client.post("/v1/orgs/invites/accept", json={"token": invite["token"]}).status_code == 409


def test_expired_invite_rejected(workspace):
    client, table, org, _, _ = workspace
    path = f"/v1/orgs/{org}/invites"
    invite = client.post(path, headers=OWNER, json={"email": "invitee@example.test", "role": "administrator"}).json()
    table.update_item(Key=org_key(org, f"INVITE#{invite['invite_id']}"),
                      UpdateExpression="SET valid_until = :past", ExpressionAttributeValues={":past": 1})
    assert client.get(path, headers=OWNER).json()[0]["status"] == "expired"
    assert client.post("/v1/orgs/invites/accept", json={"token": invite["token"]}).status_code == 409


def test_job_idempotency_quota_access_and_result(workspace):
    client, table, org, _, messages = workspace
    path = f"/v1/orgs/{org}"
    enqueue = f"{path}/connections/{ACCOUNT}/jobs"
    request_id = uuid4()
    body = {"request_id": str(request_id)}
    assert client.post(enqueue, json=body).status_code == 404
    response = client.post(enqueue, json=body, headers=OWNER)
    assert response.status_code == 202, response.text
    assert client.post(enqueue, json=body, headers=OWNER).json()["job_id"] == request_id.hex
    assert messages == [(org, request_id.hex)] * 2
    assert client.post(enqueue, json={"request_id": str(uuid4())}, headers=OWNER).status_code == 429
    calls = []
    for message in messages:
        run_job(OrgJobs(table), *message, lambda *_: calls.append(1) or sample_report())
    assert len(calls) == 1
    result = f"{path}/jobs/{request_id.hex}/result"
    assert client.get(result).status_code == 404
    assert client.get(result, headers=OWNER).json()["scan"]["account_id"] == ACCOUNT
    for _ in range(2):
        job = client.post(enqueue, json={"request_id": str(uuid4())}, headers=OWNER)
        assert job.status_code == 202
        assert client.post(f"{path}/jobs/{job.json()['job_id']}/cancel", json={}, headers=OWNER).status_code == 200
    assert client.post(enqueue, json={"request_id": str(uuid4())}, headers=OWNER).status_code == 429


def test_migration_preview_copy_and_rollback_keep_source(workspace):
    client, table, org, _, _ = workspace
    accounts = AccountStore(table)
    accounts.connect("owner", ACCOUNT)
    scans = ScanStore(table)
    legacy = tenant_key("owner", ACCOUNT)
    scan_id = scans.put_scan(sample_report(), owner=legacy)
    path = f"/v1/orgs/{org}/connections/{ACCOUNT}/migration"
    assert client.get(path).status_code == 404
    assert client.get(path, headers=OWNER).json()[0]["imported_job"] is None
    imported = client.post(path, headers=OWNER, json={"scan_id": scan_id})
    assert imported.status_code == 200, imported.text
    job_id = imported.json()["job_id"]
    assert client.post(path, headers=OWNER, json={"scan_id": scan_id}).json()["job_id"] == job_id
    job_path = f"/v1/orgs/{org}/jobs/{job_id}"
    assert client.get(f"{job_path}/result", headers=OWNER).status_code == 200
    assert client.post(f"{job_path}/rollback-import", headers=OWNER).status_code == 200
    assert client.get(f"{job_path}/result", headers=OWNER).status_code == 409
    assert scans.get_scan(legacy, scan_id)
    assert client.get(path, headers=OWNER).json()[0]["imported_job"] is None


def test_cancel_during_scan_prevents_publication(workspace):
    client, table, org, _, messages = workspace
    root = f"/v1/orgs/{org}"
    response = client.post(f"{root}/connections/{ACCOUNT}/jobs", headers=OWNER,
                           json={"request_id": str(uuid4())})
    job_id = response.json()["job_id"]

    def scan(*_):
        assert client.post(f"{root}/jobs/{job_id}/cancel", headers=OWNER, json={}).status_code == 200
        return sample_report()

    run_job(OrgJobs(table), *messages[0], scan)
    assert client.get(f"{root}/jobs/{job_id}", headers=OWNER).json()["state"] == "cancelled"
    assert client.get(f"{root}/jobs/{job_id}/result", headers=OWNER).status_code == 409


def test_membership_edits_owner_transfer_and_revocation(workspace):
    client, table, org, connection, _ = workspace
    root = f"/v1/orgs/{org}"
    issued = client.post(f"{root}/invites", headers=OWNER, json={
        "email": "invitee@example.test", "role": "viewer", "allowed_account": connection["account_connection_id"],
    }).json()
    assert client.post("/v1/orgs/invites/accept", json={"token": issued["token"]}).status_code == 200
    target = f"{root}/members/unrelated"
    assert len(client.get(f"{root}/members", headers=OWNER).json()) == 2
    assert client.patch(target, headers=OWNER, json={"role": "administrator"}).status_code == 200
    assert client.delete(f"{root}/members/owner", headers=OWNER).status_code == 409
    assert client.post(f"{target}/transfer-ownership", headers=OWNER).status_code == 200
    assert OrganizationStore(table).role("owner", org) == "administrator"
    assert OrganizationStore(table).role("unrelated", org) == "owner"
    assert client.delete(target, headers=OWNER).status_code == 409
    assert client.delete(f"{root}/members/owner").status_code == 200
    assert client.get(f"{root}/members", headers=OWNER).status_code == 404
    assert client.post("/v1/orgs/invites/accept", json={"token": issued["token"]}).status_code == 409


def test_disconnect_purges_history_blocks_inflight_and_is_generation_scoped(workspace):
    client, table, org, connection, messages = workspace
    root = f"/v1/orgs/{org}"
    path = f"{root}/connections/{ACCOUNT}"
    first = client.post(f"{path}/jobs", headers=OWNER, json={"request_id": str(uuid4())}).json()
    jobs = OrgJobs(table)
    run_job(jobs, *messages[-1], lambda *_: sample_report())
    job = jobs.job(org, first["job_id"])
    assert ScanStore(table).get_scan(job["result_owner"], job["scan_id"])
    second = client.post(f"{path}/jobs", headers=OWNER, json={"request_id": str(uuid4())}).json()
    removal = {"connection_id": connection["account_connection_id"]}
    assert client.post(f"{path}/disconnect", json=removal).status_code == 404

    def disconnect_while_running(*_):
        response = client.post(f"{path}/disconnect", headers=OWNER, json=removal)
        assert response.status_code == 202, response.text
        assert response.json()["cleanup_queued"]
        return sample_report()

    run_job(jobs, *messages[-1], disconnect_while_running)
    assert jobs.job(org, second["job_id"]) is None
    assert not ScanStore(table).get_scan(job["result_owner"], job["scan_id"])
    assert client.get(f"{root}/jobs", headers=OWNER).json() == []
    replacement = jobs.connect("owner", org, ACCOUNT, "Replacement", "us-east-1")
    assert replacement["account_connection_id"] != connection["account_connection_id"]
    assert client.post(f"{path}/disconnect", headers=OWNER, json=removal).status_code == 202
    assert jobs.connection(org, ACCOUNT)["account_connection_id"] == replacement["account_connection_id"]

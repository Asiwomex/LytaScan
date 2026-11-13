from uuid import uuid4

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from api.app import app
from api.onboarding import get_organizations, get_setup_url, get_verifier, principal
from scanner.organizations import OrganizationStore, membership_key

ACCOUNT = "111122223333"
CONNECTION = {
    "name": "Sandbox", "aws_account_id": ACCOUNT, "region": "us-east-1", "read_access_consent": True,
}


@pytest.fixture
def onboarding(table):
    store = OrganizationStore(table)
    results = []

    def verify(account, attempt):
        results.append((account["organization_id"], attempt))
        return "verified"

    def test_principal(request: Request):
        request.scope["aws.event"] = {"requestContext": {"authorizer": {"jwt": {"claims": {
            "sub": request.headers.get("test-subject"),
            "token_use": request.headers.get("test-token-use", "access"),
        }}}}}
        return principal(request)

    app.dependency_overrides.update({
        principal: test_principal,
        get_organizations: lambda: store,
        get_setup_url: lambda: lambda _: None,
        get_verifier: lambda: verify,
    })
    try:
        yield TestClient(app), store, results
    finally:
        app.dependency_overrides.clear()


def test_organization_idempotency_and_access(onboarding):
    client, _, _ = onboarding
    owner = {"test-subject": "owner"}
    other = {"test-subject": "other"}
    body = {"name": "Northwind", "request_id": str(uuid4())}
    assert client.get("/v1/orgs").status_code == 401
    assert client.get("/v1/orgs", headers={**owner, "test-token-use": "id"}).status_code == 401
    first = client.post("/v1/orgs", json=body, headers=owner)
    assert first.status_code == 201, first.text
    assert first.headers["cache-control"] == "no-store"
    assert first.json() == client.post("/v1/orgs", json=body, headers=owner).json()
    assert client.post("/v1/orgs", json={**body, "name": "Different"}, headers=owner).status_code == 409
    assert client.get("/v1/orgs", headers=other).json() == []
    path = f"/v1/orgs/{first.json()['organization_id']}/connections"
    assert client.get(path, headers=other).status_code == 404
    assert client.post(path, json=CONNECTION, headers=other).status_code == 404


def test_connection_verification_and_quota(onboarding):
    client, store, results = onboarding
    owner = {"test-subject": "owner"}
    org = store.create("owner", "Northwind", uuid4().hex)["organization_id"]
    path = f"/v1/orgs/{org}/connections"
    assert client.post(path, json={**CONNECTION, "read_access_consent": False}, headers=owner).status_code == 422
    created = client.post(path, json=CONNECTION, headers=owner)
    assert created.status_code == 201, created.text
    connection = created.json()
    assert "external_id" not in connection
    assert connection == client.post(path, json=CONNECTION, headers=owner).json()
    assert "launch_url" not in client.get(path, headers=owner).json()[0]
    target = f"{path}/{ACCOUNT}/verify"
    assert client.post(target, json={"role_arn": "different"}, headers=owner).status_code == 422
    assert client.post(target, json={"role_arn": connection["role_arn"]}, headers={"test-subject": "other"}).status_code == 404
    assert results == []
    verified = client.post(target, json={"role_arn": connection["role_arn"]}, headers=owner)
    assert verified.status_code == 200, verified.text
    assert verified.json()["status"] == "verified"
    assert verified.json()["verified_at"]
    assert client.post(target, json={"role_arn": connection["role_arn"]}, headers=owner).status_code == 429
    for suffix in ("1", "2"):
        assert client.post(path, json={**CONNECTION, "aws_account_id": ACCOUNT[:-1] + suffix}, headers=owner).status_code == 201
    assert client.post(path, json={**CONNECTION, "aws_account_id": ACCOUNT[:-1] + "4"}, headers=owner).status_code == 409
    store.table.put_item(Item={**membership_key("viewer", org), "role": "viewer", "status": "active"})
    assert client.get(path, headers={"test-subject": "viewer"}).json() == []


def test_revoked_membership_cannot_finish_verification(onboarding):
    client, store, _ = onboarding
    org = store.create("owner", "Northwind", uuid4().hex)["organization_id"]
    account = store.connect("owner", org, ACCOUNT, "Sandbox", "us-east-1")

    def revoke(*_):
        store.table.delete_item(Key=membership_key("owner", org))
        return "verified"

    app.dependency_overrides[get_verifier] = lambda: revoke
    response = client.post(
        f"/v1/orgs/{org}/connections/{ACCOUNT}/verify",
        json={"role_arn": account["role_arn"]},
        headers={"test-subject": "owner"},
    )
    assert response.status_code == 409
    assert store.connection(org, ACCOUNT)["status"] == "pending"

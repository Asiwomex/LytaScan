from uuid import uuid4

from scanner.lifecycle import FindingStore, fingerprint
from scanner.org_jobs import OrgJobs, run_job
from scanner.scan_progress import job_plan

from .test_finding_lifecycle import RULE, publish, report
from .test_m1_operations import ACCOUNT, OWNER, workspace  # noqa: F401


def test_inventory_resolution_requires_complete_matching_scope_and_reopens(workspace):
    _, table, org, connection, _ = workspace
    generation = connection["account_connection_id"]
    original = report("fail", 1)
    finding_id = fingerprint(org, generation, original["findings"][0])
    findings = FindingStore(table)
    inventory = {"resource_type": "AWS::EC2::Instance", "region": "us-east-1",
                 "account_id": ACCOUNT, "complete": True, "resource_ids": []}
    publish(table, org, connection, original)
    publish(table, org, connection, {**report(None, 2), "inventory": [inventory]})
    resolved = findings.get(org, generation, finding_id)
    assert resolved["workflow_status"] == "resolved"
    assert resolved["resolution_reason"] == "resource_deleted"
    assert resolved["outcome"] == "not_applicable"
    assert "complete inventory" in findings.history(org, generation, finding_id)[-1]["note"]
    publish(table, org, connection, report("fail", 3))
    reopened = findings.get(org, generation, finding_id)
    assert reopened["workflow_status"] == "open"
    assert "resolution_reason" not in reopened


def test_incomplete_and_wrong_inventory_cannot_close(workspace):
    _, table, org, connection, _ = workspace
    initial = report("fail", 1)
    generation = connection["account_connection_id"]
    fid = fingerprint(org, generation, initial["findings"][0])
    store = FindingStore(table)
    inventory = {"resource_type": "AWS::EC2::Instance", "region": "us-east-1",
                 "account_id": ACCOUNT, "complete": True, "resource_ids": []}
    publish(table, org, connection, initial)
    publish(table, org, connection, {**report(None, 2), "inventory": [{**inventory, "complete": False},
                                                                     {**inventory, "account_id": "000000000000"}]})
    assert store.get(org, generation, fid)["workflow_status"] == "open"
    publish(table, org, connection, {**report(None, 3, "incomplete"), "inventory": [inventory]})
    assert store.get(org, generation, fid)["workflow_status"] == "open"


def test_scope_progress_starts_settles_and_retries(workspace):
    client, table, org, _, dispatch = workspace
    base = f"/v1/orgs/{org}"
    request = f"{base}/connections/{ACCOUNT}/jobs"
    payload = {"mode": "pillar", "pillar": "security", "request_id": str(uuid4())}
    job = client.post(request, headers=OWNER, json=payload)
    assert job.status_code == 202, job.text
    job_id = job.json()["job_id"]
    plan = job_plan("us-east-1", {"kind": "pillar", "pillar": "security"})
    route = f"{base}/jobs/{job_id}/scopes"
    assert client.get(route).status_code == 404
    assert client.get(route, headers=OWNER).json()["settled"] == 0

    def scan(_connection, _region, *, progress, verification):
        assert verification["kind"] == "pillar"
        selected = next(scope for scope in plan if scope["check_id"] == RULE)
        progress({**selected, "status": "running"})
        assert client.get(route, headers=OWNER).json()["running"] == 1
        for scope in plan:
            status = "incomplete" if scope["check_id"] == RULE else "complete"
            progress({**scope, "status": status, "reason_codes": ["permission_denied"] if status == "incomplete" else []})
        return report("error", 1, "incomplete")

    run_job(OrgJobs(table), *dispatch[-1], scan, supports_progress=True)
    result = client.get(route, headers=OWNER).json()
    assert result["total"] == result["settled"] == len(plan)
    assert result["incomplete"] == 1
    chosen = next(scope for scope in result["scopes"] if scope["check_id"] == RULE)
    assert chosen["reason_codes"] == ["permission_denied"]
    retry_path = f"{base}/jobs/{job_id}/retry-scope"
    retry = client.post(retry_path, headers=OWNER, json={
        "request_id": str(uuid4()), "check_id": RULE, "region": "us-east-1",
    })
    assert retry.status_code == 202, retry.text
    assert retry.json()["kind"] == "scope_retry"
    assert retry.json()["scope_progress"]["total"] == 1
    wrong = client.post(retry_path, headers=OWNER, json={
        "request_id": str(uuid4()), "check_id": RULE, "region": "eu-west-1",
    })
    assert wrong.status_code == 409

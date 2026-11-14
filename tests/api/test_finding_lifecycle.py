import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from scanner.findings import format_timestamp
from scanner.lifecycle import FindingStore, fingerprint
from scanner.org_jobs import OrgJobs, run_job
from scanner.organizations import membership_key

from .test_m1_operations import ACCOUNT, OWNER, workspace  # noqa: F401

RULE = "ec2_imdsv2_required"


def report(status, offset, scope="complete", *, arn=None):
    at = format_timestamp(datetime.now(timezone.utc) + timedelta(seconds=offset))
    finding = {
        "check_id": RULE, "title": "EC2 instance does not require IMDSv2",
        "pillar": "security", "severity": "high", "status": status,
        "resource_arn": arn or f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-1",
        "resource_type": "AWS::EC2::Instance", "region": "us-east-1", "account_id": ACCOUNT,
        "description": f"Evidence: {status}", "remediation": "Require IMDSv2.", "scanned_at": at,
    }
    return {
        "scan": {
            "account_id": ACCOUNT, "started_at": at, "finished_at": at, "regions": ["us-east-1"],
            "checks_run": [RULE], "assessment": {
                "registry_version": "2.1.0", "planned_scopes": 1, "completed_scopes": int(scope == "complete"),
                "scopes": [{"check_id": RULE, "region": "us-east-1", "outcome": scope}],
            },
        },
        "findings": [finding] if status else [],
    }


def publish(table, org, connection, results, *, job_id=None):
    jobs = OrgJobs(table)
    job = jobs.enqueue(org, "owner", connection, job_id or uuid4().hex)
    run_job(jobs, org, job["job_id"], lambda *_: results)
    for _ in range(2):
        # Duplicate queue deliveries must not duplicate audit entries.
        run_job(jobs, org, job["job_id"], lambda *_: results)
    return jobs.job(org, job["job_id"])


def test_repeat_fail_resolve_reopen_and_no_duplicates(workspace):
    _, table, org, connection, _ = workspace
    results = report("fail", 1)
    generation = connection["account_connection_id"]
    fid = fingerprint(org, generation, results["findings"][0])
    findings = FindingStore(table)
    publish(table, org, connection, results)
    first = findings.get(org, generation, fid)
    publish(table, org, connection, report("pass", 2))
    assert findings.get(org, generation, fid)["resolution_reason"] == "confirmed_pass"
    publish(table, org, connection, report("fail", 3))
    reopened = findings.get(org, generation, fid)
    assert reopened["first_seen"] == first["first_seen"]
    assert reopened["last_seen"] > first["last_seen"]
    assert reopened["workflow_status"] == "open"
    actions = [item["action"] for item in findings.history(org, generation, fid)]
    assert sorted(actions) == ["opened", "reopened", "resolved"]


def test_partial_missing_and_unavailable_do_not_resolve(workspace):
    _, table, org, connection, _ = workspace
    results = report("fail", 1)
    generation = connection["account_connection_id"]
    fid = fingerprint(org, generation, results["findings"][0])
    findings = FindingStore(table)
    publish(table, org, connection, results)
    publish(table, org, connection, report("pass", 2, "incomplete"))
    partial = findings.get(org, generation, fid)
    assert partial["workflow_status"] == "open"
    assert partial["outcome"] == "unknown"
    assert partial["evidence"] == "Evidence: fail"
    publish(table, org, connection, report(None, 3))
    assert findings.get(org, generation, fid)["last_observed_at"] == partial["last_observed_at"]


def test_scoped_workflow_comments_expiry_and_verification(workspace):
    client, table, org, connection, messages = workspace
    results = report("fail", 1)
    publish(table, org, connection, results)
    root = f"/v1/orgs/{org}/connections/{ACCOUNT}/findings"
    item = client.get(root, headers=OWNER).json()["findings"][0]
    path = f"{root}/{item['finding_id']}"
    assert client.get(path).status_code == 404
    viewer = {"test-subject": "viewer"}
    table.put_item(Item={**membership_key("viewer", org), "status": "active", "role": "viewer",
                         "allowed_account": connection["account_connection_id"]})
    assert client.get(path, headers=viewer).status_code == 200
    assert client.patch(path, headers=viewer, json={"status": "acknowledged", "revision": item["revision"]}).status_code == 403
    assert client.patch(path, headers=OWNER, json={"status": "resolved", "revision": item["revision"]}).status_code == 422
    assert client.patch(path, headers=OWNER, json={"status": "suppressed", "revision": item["revision"]}).status_code == 422
    expiry = int(time.time()) + 60
    response = client.patch(path, headers=OWNER, json={
        "status": "suppressed", "revision": item["revision"], "reason": "Planned maintenance", "expires_at": expiry,
    })
    assert response.status_code == 200, response.text
    assert response.json()["outcome"] == "fail"
    assert client.post(f"{path}/comments", headers=OWNER, json={"note": "Owner reviewed the exception."}).status_code == 201
    assert client.patch(path, headers=OWNER, json={"status": "acknowledged", "revision": item["revision"]}).status_code == 409
    history = client.get(path, headers=OWNER).json()["history"]
    assert [event["action"] for event in history] == ["commented", "workflow_changed", "opened"]
    queued = client.post(f"{path}/verify", headers=OWNER, json={"request_id": str(uuid4())})
    assert queued.status_code == 202, queued.text
    run_job(OrgJobs(table), *messages[-1], lambda *_, verification: report("pass", 2))
    assert client.get(path, headers=OWNER).json()["workflow_status"] == "resolved"
    assert client.get(f"{root}?status=resolved&limit=1", headers=OWNER).json()["findings"][0]["finding_id"] == item["finding_id"]


def test_expired_suppression_is_open_without_changing_the_evaluation(workspace, monkeypatch):
    client, table, org, connection, _ = workspace
    publish(table, org, connection, report("fail", 1))
    root = f"/v1/orgs/{org}/connections/{ACCOUNT}/findings"
    item = client.get(root, headers=OWNER).json()["findings"][0]
    path = f"{root}/{item['finding_id']}"
    expires_at = int(time.time()) + 60
    assert client.patch(path, headers=OWNER, json={
        "status": "risk_accepted", "revision": item["revision"], "reason": "Temporary waiver", "expires_at": expires_at,
    }).status_code == 200
    with monkeypatch.context() as patch:
        patch.setattr("scanner.lifecycle.time.time", lambda: expires_at + 1)
        expired = client.get(f"{root}?status=open", headers=OWNER).json()["findings"][0]
    assert expired["workflow_status"] == "open"
    assert expired["outcome"] == "fail"
    assert expired["exception_until"] is None


def test_fingerprint_keeps_account_region_and_key_identity():
    base = report("fail", 1)["findings"][0]
    assert fingerprint("org", "conn", base) != fingerprint("org", "other", base)
    assert fingerprint("org", "conn", base) == fingerprint("org", "conn", {**base, "resource_arn": base["resource_arn"] + ":*"})
    assert fingerprint("org", "conn", {**base, "resource_id": "key1"}) != fingerprint("org", "conn", {**base, "resource_id": "key2"})

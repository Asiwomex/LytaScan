from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.check import CheckContext
from scanner.checks import cloudwatch_alarm_actions, ec2_ebs_optimization, s3_incomplete_multipart_cleanup
from scanner.coverage import assessment
from scanner.findings import Status
from scanner.registry import catalog, markdown_catalog
from pathlib import Path
from scanner.store import ScanStore


def test_catalog_covers_all_six_pillars():
    checks = list(catalog())
    assert len(checks) == len({item["check_id"] for item in checks})
    assert len(checks) >= 60
    assert all(item["required_actions"] for item in checks)
    assert len({item["primary_pillar"] for item in checks}) == 6


def test_generated_catalog_is_current():
    path = Path(__file__).resolve().parents[2] / "docs" / "check-catalog.md"
    assert path.read_text(encoding="utf-8").strip() == markdown_catalog().strip()


def test_alarm_action_state_including_missing_data():
    session = Mock()
    alarms = [
        {"AlarmArn": str(index), "AlarmActions": ["action"], **fields}
        for index, fields in enumerate([{"ActionsEnabled": True}, {"ActionsEnabled": False}, {}])
    ]
    session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {"MetricAlarms": alarms[:1]}, {"MetricAlarms": [*alarms[1:], {"AlarmArn": "no-actions"}]},
    ]
    ctx = CheckContext(session, "111122223333", "us-east-1", datetime.now(timezone.utc))
    assert [item.status for item in cloudwatch_alarm_actions.run(ctx)] == [Status.PASS, Status.FAIL, Status.UNKNOWN]


def test_ebs_optimization_caches_capabilities_and_excludes_default():
    session = Mock()
    ec2 = session.client.return_value
    instances = [
        {"InstanceId": str(index), "InstanceType": kind, **flag}
        for index, (kind, flag) in enumerate([
            ("optional", {"EbsOptimized": True}), ("optional", {"EbsOptimized": False}), ("optional", {}),
            ("automatic", {"EbsOptimized": False}),
        ])
    ]
    ec2.get_paginator.return_value.paginate.return_value = [{"Reservations": [{"Instances": instances}]}]
    ec2.describe_instance_types.side_effect = [
        {"InstanceTypes": [{"EbsInfo": {"EbsOptimizedSupport": kind}}]} for kind in ["supported", "default"]
    ]
    ctx = CheckContext(session, "111122223333", "us-east-1", datetime.now(timezone.utc))
    assert [item.status for item in ec2_ebs_optimization.run(ctx)] == [Status.PASS, Status.FAIL, Status.UNKNOWN]
    assert ec2.describe_instance_types.call_count == 2


def test_s3_multipart_cleanup_distinguishes_partial_scope(session):
    s3 = session.client("s3")
    for name in ("without-rules", "filtered-rule", "bucket-wide-rule"):
        s3.create_bucket(Bucket=name)
    for name, prefix in (("filtered-rule", "uploads/"), ("bucket-wide-rule", "")):
        s3.put_bucket_lifecycle_configuration(Bucket=name, LifecycleConfiguration={"Rules": [{
            "ID": "abort", "Status": "Enabled", "Filter": {"Prefix": prefix},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
        }]})
    ctx = CheckContext(session, "111122223333", "global", datetime.now(timezone.utc))
    assert {item.resource_arn.split(":")[-1]: item.status for item in s3_incomplete_multipart_cleanup.run(ctx)} == {
        "without-rules": Status.FAIL, "filtered-rule": Status.FAIL, "bucket-wide-rule": Status.PASS,
    }


def test_coverage_ignores_inapplicable_and_preserves_decimals(table):
    ctx = CheckContext(Mock(), "111122223333", "us-east-1", datetime.now(timezone.utc))
    findings = [
        ctx.finding(cloudwatch_alarm_actions.META, status, str(index), "test")
        for index, status in enumerate([Status.PASS, Status.FAIL, Status.UNKNOWN, Status.NOT_APPLICABLE])
    ]
    scopes = [{"pillar": cloudwatch_alarm_actions.META.pillar.value, "outcome": "incomplete"}]
    result = assessment(findings, scopes)
    assert result["evaluated_pillars"] == 1
    assert result["overall_score"] == 50
    assert result["completed_scopes"] == 0
    operational = next(pillar for pillar in result["pillars"] if pillar["pillar"] == "operational_excellence")
    assert operational["coverage"] == 66.67
    report = {"scan": {"account_id": ctx.account_id, "started_at": findings[0].scanned_at,
                       "finished_at": findings[0].scanned_at, "regions": [ctx.region],
                       "checks_run": [], "assessment": result}, "findings": [item.to_dict() for item in findings]}
    store = ScanStore(table)
    scan_id = store.put_scan(report, owner="m2")
    assert store.get_scan("m2", scan_id)["scan"]["assessment"] == result

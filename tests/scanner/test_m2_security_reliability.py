"""Fixture tests for the v2 security and reliability configuration rules."""

from datetime import datetime, timezone
from importlib import import_module
from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.check import CheckContext
from scanner.engine import Check, run_check
from scanner.findings import Status


def module(name):
    return import_module(f"scanner.checks.{name}")


def denied():
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "fixture denied"}}, "Read")


def context():
    session = Mock()
    return CheckContext(session, "123456789012", "us-east-1", datetime.now(timezone.utc)), session.client.return_value


def pages(client, key, values):
    # Every configured fixture has separate pages to verify complete iteration.
    client.get_paginator.return_value.paginate.return_value = [{key: values[:1]}, {key: values[1:]}]


def statuses(name, ctx):
    check = module(name)
    return [result.status for result in check.run(ctx)]


@pytest.mark.parametrize(("indicator", "expected"), [
    (0, Status.PASS), (1, Status.FAIL), (None, Status.UNKNOWN),
])
def test_root_access_key_summary(indicator, expected):
    ctx, iam = context()
    iam.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": indicator}}
    assert statuses("iam_root_access_keys", ctx) == [expected]


def test_imdsv2_requires_applied_configuration_and_handles_disabled_endpoints():
    ctx, ec2 = context()
    options = [
        {"HttpEndpoint": "enabled", "HttpTokens": "required", "State": "applied"},
        {"HttpEndpoint": "enabled", "HttpTokens": "optional", "State": "applied"},
        {"HttpEndpoint": "disabled", "State": "applied"},
        {"HttpEndpoint": "enabled", "HttpTokens": "required", "State": "pending"},
        {},
    ]
    instances = [{"InstanceId": str(i), "MetadataOptions": value} for i, value in enumerate(options)]
    instances.append({"InstanceId": "deleted", "State": {"Name": "terminated"}})
    pages(ec2, "Reservations", [{"Instances": instances[:2]}, {"Instances": instances[2:]}])
    assert statuses("ec2_imdsv2_required", ctx) == [
        Status.PASS, Status.FAIL, Status.PASS, Status.UNKNOWN, Status.UNKNOWN,
    ]


@pytest.mark.parametrize(("check", "operation", "key", "id_field", "attribute", "applicable", "excluded"), [
    ("ebs_volume_encryption", "describe_volumes", "Volumes", "VolumeId", "Encrypted",
     {"State": "in-use"}, {"State": "deleting"}),
    ("rds_storage_encryption", "describe_db_instances", "DBInstances", "DBInstanceArn", "StorageEncrypted",
     {}, {"DBClusterIdentifier": "cluster"}),
    ("rds_deletion_protection", "describe_db_instances", "DBInstances", "DBInstanceArn", "DeletionProtection",
     {}, {"DBInstanceStatus": "deleting"}),
])
def test_boolean_metadata_checks(check, operation, key, id_field, attribute, applicable, excluded):
    ctx, client = context()
    rows = [{id_field: str(i), attribute: value, **applicable} for i, value in enumerate([True, False, None])]
    rows.append({id_field: "excluded", attribute: False, **excluded})
    pages(client, key, rows)
    assert statuses(check, ctx) == [Status.PASS, Status.FAIL, Status.UNKNOWN]
    client.get_paginator.assert_called_once_with(operation)


@pytest.mark.parametrize(("check", "attribute", "enabled", "disabled", "missing"), [
    ("cloudtrail_log_validation", "LogFileValidationEnabled", True, False, Status.UNKNOWN),
    ("cloudtrail_kms_encryption", "KmsKeyId", "key", "", Status.FAIL),
])
def test_cloudtrail_only_evaluates_home_region(check, attribute, enabled, disabled, missing):
    ctx, cloudtrail = context()
    cloudtrail.describe_trails.return_value = {"trailList": [
        {"TrailARN": "first", "HomeRegion": ctx.region, attribute: enabled},
        {"TrailARN": "second", "HomeRegion": ctx.region, attribute: disabled},
        {"TrailARN": "incomplete", "HomeRegion": ctx.region},
        {"TrailARN": "shadow", "HomeRegion": "us-west-2", attribute: disabled},
    ]}
    assert statuses(check, ctx) == [Status.PASS, Status.FAIL, missing]
    cloudtrail.describe_trails.assert_called_once_with(includeShadowTrails=False)


def test_ecr_mutability_including_partial_exclusions():
    ctx, ecr = context()
    modes = ["IMMUTABLE", "IMMUTABLE_WITH_EXCLUSION", "MUTABLE_WITH_EXCLUSION", "MUTABLE", None]
    pages(ecr, "repositories", [{"repositoryArn": str(i), "imageTagMutability": mode}
                                for i, mode in enumerate(modes)])
    assert statuses("ecr_immutable_tags", ctx) == [
        Status.PASS, Status.FAIL, Status.FAIL, Status.FAIL, Status.UNKNOWN,
    ]


def test_dynamodb_deletion_protection_handles_unreadable_tables():
    ctx, dynamodb = context()
    pages(dynamodb, "TableNames", ["protected", "unprotected", "missing", "denied", "deleted"])
    dynamodb.describe_table.side_effect = [
        {"Table": {"DeletionProtectionEnabled": True}},
        {"Table": {"DeletionProtectionEnabled": False}},
        {"Table": {}},
        denied(),
        {"Table": {"TableStatus": "DELETING"}},
    ]
    assert statuses("dynamodb_deletion_protection", ctx) == [
        Status.PASS, Status.FAIL, Status.UNKNOWN, Status.ERROR,
    ]


def test_efs_backup_policy_distinguishes_absent_transition_and_denied():
    ctx, efs = context()
    rows = [{"FileSystemId": str(i), "LifeCycleState": "available"} for i in range(5)]
    rows.append({"FileSystemId": "deleted", "LifeCycleState": "deleting"})
    pages(efs, "FileSystems", rows)
    efs.describe_backup_policy.side_effect = [
        {"BackupPolicy": {"Status": "ENABLED"}},
        {"BackupPolicy": {"Status": "DISABLED"}},
        {"BackupPolicy": {"Status": "ENABLING"}},
        ClientError({"Error": {"Code": "PolicyNotFound", "Message": "fixture absent"}}, "DescribeBackupPolicy"),
        denied(),
    ]
    assert statuses("efs_automatic_backup", ctx) == [Status.PASS, Status.FAIL, Status.UNKNOWN, Status.FAIL, Status.ERROR]


def test_autoscaling_health_excludes_pending_instances():
    ctx, autoscaling = context()
    groups = [{"AutoScalingGroupARN": str(i), "Instances": [
        {"LifecycleState": "InService", "HealthStatus": state},
        {"LifecycleState": "Pending", "HealthStatus": "Unhealthy"},
    ]} for i, state in enumerate(["Healthy", "Unhealthy", None])]
    groups.append({"AutoScalingGroupARN": "empty", "Instances": [{"LifecycleState": "Pending"}]})
    pages(autoscaling, "AutoScalingGroups", groups)
    assert statuses("autoscaling_unhealthy_instances", ctx) == [Status.PASS, Status.FAIL, Status.UNKNOWN]


def test_elb_health_excludes_unattached_empty_and_draining_targets():
    ctx, elb = context()
    groups = [{"TargetGroupArn": str(i), "LoadBalancerArns": ["lb"]} for i in range(5)]
    groups.append({"TargetGroupArn": "unattached", "LoadBalancerArns": []})
    pages(elb, "TargetGroups", groups)
    elb.describe_target_health.side_effect = [
        {"TargetHealthDescriptions": [{"TargetHealth": {"State": state}} for state in states]}
        for states in [["healthy", "draining"], ["unhealthy", "healthy"], ["initial"], ["unused"]]
    ] + [denied()]
    assert statuses("elb_unhealthy_targets", ctx) == [Status.PASS, Status.FAIL, Status.UNKNOWN, Status.ERROR]
    assert elb.describe_target_health.call_count == 5


def test_sqs_only_checks_queues_with_explicit_requirement():
    ctx, sqs = context()
    pages(sqs, "QueueUrls", [f"https://sqs.us-east-1.amazonaws.com/123456789012/fixture-{i}" for i in range(5)])
    tags = {"Tags": {"PillarscanRequireDlq": "true"}}
    sqs.list_queue_tags.side_effect = [tags, tags, tags, {}, denied()]
    sqs.get_queue_attributes.side_effect = [
        {"Attributes": {"RedrivePolicy": '{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:123456789012:dead","maxReceiveCount":3}'}},
        {"Attributes": {}},
        {"Attributes": {"RedrivePolicy": "{}"}},
    ]
    assert statuses("sqs_required_dead_letter_queue", ctx) == [Status.PASS, Status.FAIL, Status.UNKNOWN, Status.ERROR]
    assert sqs.get_queue_attributes.call_count == 3


@pytest.mark.parametrize("name", [
    "iam_root_access_keys", "ec2_imdsv2_required", "ebs_volume_encryption",
    "rds_storage_encryption", "cloudtrail_log_validation", "cloudtrail_kms_encryption",
    "ecr_immutable_tags", "rds_deletion_protection", "dynamodb_deletion_protection",
    "efs_automatic_backup", "autoscaling_unhealthy_instances", "elb_unhealthy_targets",
    "sqs_required_dead_letter_queue",
])
def test_listing_permission_denial_is_reported_as_error(name):
    ctx, client = context()
    for operation in ("get_paginator", "get_account_summary", "describe_trails"):
        getattr(client, operation).side_effect = denied()
    check = module(name)
    outcome = run_check(Check(meta=check.META, run=check.run), ctx)
    assert [finding.status for finding in outcome] == [Status.ERROR]

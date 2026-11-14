from datetime import datetime, timedelta, timezone
from importlib import import_module

from botocore.exceptions import ClientError
import pytest

from scanner.check import CheckContext
from scanner.checks import s3_noncurrent_version_lifecycle
from scanner.efficiency_metrics import Target
from scanner.findings import Status

ACCOUNT = "123456789012"
REGION = "us-east-1"
ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-test"
NOW = datetime(2026, 10, 12, 8, 0, tzinfo=timezone.utc)
GIB = 1024 ** 3
HOURLY_MIB = 3600 * 1024 ** 2


class MetricClient:
    def __init__(self, values, sample_count, error=None):
        self.values = values
        self.sample_count = sample_count
        self.error = error
        self.requests = []

    def get_paginator(self, name):
        assert name == "get_metric_data"
        return self

    def paginate(self, **request):
        self.requests.append(request)
        if self.error:
            raise self.error
        results = []
        for entry, value in zip(request["MetricDataQueries"], self.values, strict=True):
            assert entry["MetricStat"]["Period"] == 3600
            stamps = [request["StartTime"] + timedelta(hours=index) for index in range(self.sample_count)]
            results.append({"Id": entry["Id"], "StatusCode": "Complete", "Timestamps": stamps, "Values": [value] * len(stamps)})
        # A long window can cross a CloudWatch page boundary.
        yield {"NextToken": "next-page", "MetricDataResults": [
            {**entry, "StatusCode": "PartialData", "Timestamps": entry["Timestamps"][:170], "Values": entry["Values"][:170]}
            for entry in results
        ]}
        yield {"MetricDataResults": [
            {**entry, "Timestamps": entry["Timestamps"][170:], "Values": entry["Values"][170:]}
            for entry in results
        ]}


class VolumeClient:
    def get_paginator(self, name):
        assert name == "describe_volumes"
        return self

    def paginate(self, **request):
        assert {"Name": "volume-type", "Values": ["gp3"]} in request["Filters"]
        yield {"Volumes": [{"VolumeId": "vol-test", "Throughput": 250}, {"VolumeId": "vol-baseline", "Throughput": 125}]}


class Session:
    def __init__(self, metrics):
        self.metrics = metrics

    def client(self, name, **_):
        if name == "cloudwatch":
            return self.metrics
        assert name == "ec2"
        return VolumeClient()


METRIC_CASES = [
    ("ec2_cpu_pressure", "targets", [30], [95], "CPUUtilization"),
    ("rds_cpu_pressure", "rds_targets", [30], [95], "CPUUtilization"),
    ("rds_free_storage_pressure", "rds_instances", [30 * GIB], [5 * GIB], "FreeStorageSpace"),
    ("lambda_throttle_pressure", "lambda_functions", [0, 200], [10, 100], "Throttles"),
    ("lambda_duration_headroom", "lambda_timeout_targets", [100], [950], "Duration"),
    ("dynamodb_read_throttle_pressure", "dynamodb_tables", [0], [1], "ReadThrottleEvents"),
    ("dynamodb_write_throttle_pressure", "dynamodb_tables", [0], [1], "WriteThrottleEvents"),
    ("ecs_cpu_pressure", "ecs_services", [30], [95], "CPUUtilization"),
    ("ecs_memory_pressure", "ecs_services", [30], [95], "MemoryUtilization"),
    ("ebs_gp3_throughput_review", None, [100 * HOURLY_MIB, 30 * HOURLY_MIB], [10 * HOURLY_MIB, 5 * HOURLY_MIB], "VolumeReadBytes"),
]


@pytest.mark.parametrize(("name", "inventory", "healthy", "unhealthy", "metric"), METRIC_CASES)
@pytest.mark.parametrize("status", [Status.PASS, Status.FAIL, Status.UNKNOWN, Status.ERROR])
def test_each_metric_rule_evaluates_observations(monkeypatch, name, inventory, healthy, unhealthy, metric, status):
    module = import_module(f"scanner.checks.{name}")
    for env in ("METRIC_LOOKBACK_DAYS", "METRIC_TARGET_LIMIT", *module.REGISTRY["thresholds"]):
        monkeypatch.delenv(f"PILLARSCAN_{env}", raising=False)
    if inventory == "rds_instances":
        resources = [{"DBInstanceArn": ARN, "DBInstanceIdentifier": "db", "AllocatedStorage": 100}]
    elif inventory == "lambda_functions":
        resources = [{"FunctionArn": ARN, "FunctionName": "fn"}]
    else:
        resources = [Target(ARN, (("Name", "test"),), 1)]
    if inventory:
        monkeypatch.setattr(module, inventory, lambda _: resources)
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetMetricData") if status == Status.ERROR else None
    client = MetricClient(unhealthy if status == Status.FAIL else healthy, 15 if status == Status.UNKNOWN else 336, error)
    ctx = CheckContext(Session(client), ACCOUNT, REGION, NOW, safe_errors=True)

    findings = list(module.run(ctx))

    assert len(findings) == 1
    assert findings[0].status == status
    assert client.requests[0]["MetricDataQueries"][0]["MetricStat"]["Metric"]["MetricName"] == metric
    if status == Status.UNKNOWN:
        assert findings[0].reason_code == "insufficient_metrics"
    if status == Status.ERROR:
        assert findings[0].reason_code == "permission_denied"


def test_metric_rule_reports_target_limit(monkeypatch):
    module = import_module("scanner.checks.ec2_cpu_pressure")
    monkeypatch.setenv("PILLARSCAN_METRIC_TARGET_LIMIT", "1")
    monkeypatch.setattr(module, "targets", lambda _: [Target(ARN, (("InstanceId", "i-first"),)), Target("second", (("InstanceId", "i-second"),))])
    client = MetricClient([0], 336)
    ctx = CheckContext(Session(client), ACCOUNT, REGION, NOW)
    assert [finding.status for finding in module.run(ctx)] == [Status.SKIPPED, Status.PASS]
    assert len(client.requests[0]["MetricDataQueries"]) == 1


def test_noncurrent_bucket_lifecycle_covers_versioning_and_rule_scope(session, make_ctx):
    s3 = session.client("s3")
    cases = {
        "with-transition": ("Enabled", {"NoncurrentVersionTransitions": [{"NoncurrentDays": 90, "StorageClass": "STANDARD_IA"}]}, Status.PASS),
        "with-expiration": ("Suspended", {"NoncurrentVersionExpiration": {"NoncurrentDays": 365}}, Status.PASS),
        "without-lifecycle": ("Enabled", None, Status.FAIL),
        "unversioned-bucket": (None, None, None),
        "filtered-expiration": ("Enabled", {"NoncurrentVersionExpiration": {"NoncurrentDays": 90}, "Filter": {"Prefix": "only/"}}, Status.FAIL),
        "disabled-expiration": ("Enabled", {"NoncurrentVersionExpiration": {"NoncurrentDays": 90}, "Status": "Disabled"}, Status.FAIL),
    }
    for bucket, (versioning, rule, _) in cases.items():
        s3.create_bucket(Bucket=bucket)
        if versioning:
            s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": versioning})
        if rule:
            s3.put_bucket_lifecycle_configuration(
                Bucket=bucket, LifecycleConfiguration={"Rules": [{"ID": "policy", "Status": "Enabled", "Filter": {}, **rule}]},
            )
    found = {item.resource_arn.split(":")[-1]: item.status for item in s3_noncurrent_version_lifecycle.run(make_ctx())}
    assert found == {bucket: expected for bucket, (_, _, expected) in cases.items() if expected is not None}

"""Assess observed read throttling on base DynamoDB tables."""

from scanner.check import CheckMeta, Scope
from scanner.efficiency_metrics import Metric, measure, metric_registry, setting
from scanner.efficiency_resources import dynamodb_tables
from scanner.findings import Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "dynamodb_read_throttle_pressure", "DynamoDB table read throttling exceeds the review threshold",
    Pillar.PERFORMANCE_EFFICIENCY, Severity.MEDIUM, "AWS::DynamoDB::Table", Scope.REGIONAL,
    "Review hot partitions, request traffic and capacity mode before changing throughput or retry behavior.",
)
REGISTRY = metric_registry(
    "dynamodb", ("dynamodb:ListTables",), "Base DynamoDB tables, excluding global secondary indexes",
    ("ReadThrottleEvents",), "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/metrics-dimensions.html",
    thresholds={"DYNAMODB_READ_THROTTLE_EVENTS": 10}, advisory=True,
)
METRICS = (Metric("ReadThrottleEvents", "Sum", "Count"),)


def run(ctx):
    threshold = setting("DYNAMODB_READ_THROTTLE_EVENTS", 10, 1, 1000000)

    def evaluate(_target, samples):
        value = sum(samples[0])
        return value < threshold, f"Observed {value:g} throttled read events; review threshold {threshold} events over the window."

    yield from measure(ctx, META, dynamodb_tables(ctx), "AWS/DynamoDB", METRICS, evaluate)

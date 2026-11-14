"""Assess observed RDS CPUUtilization pressure."""

from scanner.check import CheckMeta, Scope
from scanner.efficiency_metrics import Metric, measure, metric_registry, percentile, setting
from scanner.efficiency_resources import rds_targets
from scanner.findings import Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "rds_cpu_pressure", "RDS CPU utilization exceeds the review threshold",
    Pillar.PERFORMANCE_EFFICIENCY, Severity.MEDIUM, "AWS::RDS::DBInstance", Scope.REGIONAL,
    "Review workload peaks, query plans, and capacity before changing the database instance size.",
)
REGISTRY = metric_registry(
    "rds", ("rds:DescribeDBInstances",), "Available RDS DB instances", ("CPUUtilization",),
    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-metrics.html",
    thresholds={"RDS_CPU_PERCENT": 85}, advisory=True,
)
METRICS = (Metric("CPUUtilization", "Average", "Percent"),)

def run(ctx):
    threshold = setting("RDS_CPU_PERCENT", 85, 1, 100)

    def evaluate(_target, samples):
        value = percentile(samples[0], 0.95)
        return value < threshold, f"95th percentile of hourly averages was {value:.1f}%; review threshold {threshold}%."

    yield from measure(ctx, META, rds_targets(ctx), "AWS/RDS", METRICS, evaluate)

"""Review observed free storage against allocated DB instance storage."""

from scanner.check import CheckMeta, Scope
from scanner.efficiency_metrics import Metric, Target, measure, metric_registry, percentile, setting
from scanner.efficiency_resources import rds_instances
from scanner.findings import Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "rds_free_storage_pressure", "RDS instance has low observed free storage",
    Pillar.PERFORMANCE_EFFICIENCY, Severity.MEDIUM, "AWS::RDS::DBInstance", Scope.REGIONAL,
    "Investigate storage growth, retention, and autoscaling limits before adjusting allocated storage.",
)
REGISTRY = metric_registry(
    "rds", ("rds:DescribeDBInstances",), "Available non-cluster RDS instances with provisioned storage",
    ("FreeStorageSpace", "AllocatedStorage"), "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-metrics.html",
    thresholds={"RDS_FREE_STORAGE_PERCENT": 15}, advisory=True,
)
METRICS = (Metric("FreeStorageSpace", "Minimum", "Bytes"),)


def run(ctx):
    threshold = setting("RDS_FREE_STORAGE_PERCENT", 15, 1, 100)
    targets = []
    for db in rds_instances(ctx):
        if db.get("DBClusterIdentifier") or db.get("Engine", "").startswith("aurora"):
            continue
        size = db.get("AllocatedStorage")
        arn = db["DBInstanceArn"]
        if not size:
            yield ctx.finding(META, Status.UNKNOWN, arn, "Allocated storage was unavailable.")
            continue
        targets.append(Target(arn, (("DBInstanceIdentifier", db["DBInstanceIdentifier"]),), size * (1024 ** 3)))

    def evaluate(target, samples):
        value = 100 * percentile(samples[0], 0.05) / target.limit
        return value >= threshold, (
            f"5th percentile of hourly minimum free bytes was {value:.1f}% of current allocated storage; "
            f"review threshold {threshold}%. Provisioned capacity may have changed during this window."
        )

    yield from measure(ctx, META, targets, "AWS/RDS", METRICS, evaluate)

"""Assess observed ECS MemoryUtilization pressure."""

from scanner.check import CheckMeta, Scope
from scanner.efficiency_metrics import Metric, measure, metric_registry, percentile, setting
from scanner.efficiency_resources import ecs_services
from scanner.findings import Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "ecs_memory_pressure", "ECS service memory utilization exceeds the review threshold",
    Pillar.PERFORMANCE_EFFICIENCY, Severity.MEDIUM, "AWS::ECS::Service", Scope.REGIONAL,
    "Review memory reservations, task sizing, and any out-of-memory events before changing capacity.",
)
REGISTRY = metric_registry(
    "ecs", ("ecs:ListClusters", "ecs:ListServices", "ecs:DescribeServices",), "Active ECS services with running tasks", ("MemoryUtilization",),
    "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service_utilization.html",
    thresholds={"ECS_MEMORY_PERCENT": 85}, advisory=True,
)
METRICS = (Metric("MemoryUtilization", "Average", "Percent"),)

def run(ctx):
    threshold = setting("ECS_MEMORY_PERCENT", 85, 1, 100)

    def evaluate(_target, samples):
        value = percentile(samples[0], 0.95)
        return value < threshold, f"95th percentile of hourly averages was {value:.1f}%; review threshold {threshold}%."

    yield from measure(ctx, META, ecs_services(ctx), "AWS/ECS", METRICS, evaluate)

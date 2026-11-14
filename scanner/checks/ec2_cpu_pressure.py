"""Assess observed EC2 CPUUtilization pressure."""

from scanner.check import CheckMeta, Scope
from scanner.efficiency_metrics import Metric, Target, measure, metric_registry, percentile, setting
from scanner.efficiency_resources import instances
from scanner.findings import Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "ec2_cpu_pressure", "EC2 CPU utilization exceeds the review threshold",
    Pillar.PERFORMANCE_EFFICIENCY, Severity.MEDIUM, "AWS::EC2::Instance", Scope.REGIONAL,
    "Compare CPU utilization with workload latency, scaling behavior, and burst credits before changing capacity.",
)
REGISTRY = metric_registry(
    "ec2", ("ec2:DescribeInstances",), "Running EC2 instances", ("CPUUtilization",),
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html",
    thresholds={"EC2_CPU_PERCENT": 85}, advisory=True,
)
METRICS = (Metric("CPUUtilization", "Average", "Percent"),)

def targets(ctx):
    for instance in instances(ctx, "running"):
        instance_id = instance["InstanceId"]
        yield Target(ctx.arn("ec2", f"instance/{instance_id}"), (("InstanceId", instance_id),))


def run(ctx):
    threshold = setting("EC2_CPU_PERCENT", 85, 1, 100)

    def evaluate(_target, samples):
        value = percentile(samples[0], 0.95)
        return value < threshold, f"95th percentile of hourly averages was {value:.1f}%; review threshold {threshold}%."

    yield from measure(ctx, META, targets(ctx), "AWS/EC2", METRICS, evaluate)

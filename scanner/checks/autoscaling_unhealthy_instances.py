"""Check the health state of instances currently in service in Auto Scaling groups."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import items
from scanner.findings import Finding, Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "autoscaling_unhealthy_instances", "Auto Scaling group has unhealthy in-service instances",
    Pillar.RELIABILITY, Severity.HIGH, "AWS::AutoScaling::AutoScalingGroup", Scope.REGIONAL,
    "Review Auto Scaling activity and its configured health checks to identify the cause.",
)
REGISTRY = {
    "service": "autoscaling",
    "required_actions": ("autoscaling:DescribeAutoScalingGroups",),
    "applicability": "Auto Scaling groups with instances in the InService lifecycle state",
    "evidence_fields": ("Instances[].HealthStatus", "Instances[].LifecycleState"),
    "references": ("https://docs.aws.amazon.com/autoscaling/ec2/userguide/health-checks-overview.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    for group in items(ctx.client("autoscaling"), "describe_auto_scaling_groups", "AutoScalingGroups"):
        states = [instance.get("HealthStatus") for instance in group.get("Instances", [])
                  if instance.get("LifecycleState") == "InService"]
        if not states:
            continue
        unhealthy = states.count("Unhealthy")
        if unhealthy:
            status, description = Status.FAIL, f"{unhealthy} of {len(states)} in-service instances are unhealthy."
        elif all(state == "Healthy" for state in states):
            status, description = Status.PASS, "All in-service instances are healthy."
        else:
            status, description = Status.UNKNOWN, "One or more in-service instances have an unrecognized health state."
        yield ctx.finding(META, status, group["AutoScalingGroupARN"], description)

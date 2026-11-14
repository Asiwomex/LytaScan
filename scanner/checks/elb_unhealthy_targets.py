"""Check target health for groups attached to Application or Network Load Balancers."""

from collections.abc import Iterator

from botocore.exceptions import ClientError

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import items
from scanner.findings import Finding, Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "elb_unhealthy_targets", "Load balancer target group has unhealthy targets",
    Pillar.RELIABILITY, Severity.HIGH, "AWS::ElasticLoadBalancingV2::TargetGroup", Scope.REGIONAL,
    "Review target health reasons and health-check settings, then fix or replace unhealthy targets.",
)
REGISTRY = {
    "service": "elasticloadbalancing",
    "required_actions": ("elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth"),
    "applicability": "Attached ALB/NLB target groups with registered targets; excludes draining and unused targets",
    "evidence_fields": ("LoadBalancerArns", "TargetHealth.State"),
    "references": ("https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetHealth.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    elb = ctx.client("elbv2")
    for group in items(elb, "describe_target_groups", "TargetGroups"):
        if group.get("Protocol") == "GENEVE" or not group.get("LoadBalancerArns"):
            continue
        arn = group["TargetGroupArn"]
        try:
            targets = elb.describe_target_health(TargetGroupArn=arn)["TargetHealthDescriptions"]
        except ClientError as error:
            yield ctx.error(META, arn, error)
            continue
        states = [target.get("TargetHealth", {}).get("State") for target in targets]
        evaluated = [state for state in states if state not in {"draining", "unused"}]
        if not evaluated:
            continue
        unhealthy = sum(state in {"unhealthy", "unhealthy.draining"} for state in evaluated)
        if unhealthy:
            status, description = Status.FAIL, f"{unhealthy} of {len(evaluated)} active targets are unhealthy."
        elif all(state == "healthy" for state in evaluated):
            status, description = Status.PASS, "All active targets are healthy."
        else:
            status, description = Status.UNKNOWN, "Target health is unavailable or transitioning."
        yield ctx.finding(META, status, arn, description)

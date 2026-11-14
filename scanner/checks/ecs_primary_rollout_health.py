"""Observe failed primary deployments for ECS rolling services."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import ecs_rolling_services

V2_ONLY = True
REGISTRY = {
    "service": "ecs",
    "required_actions": ["ecs:ListClusters", "ecs:ListServices", "ecs:DescribeServices"],
    "applicability": "Active ECS-controlled rolling replica services with desired tasks",
    "evidence_fields": ["deployments[].status", "deployments[].rolloutState"],
    "references": ["https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html"],
}
META = CheckMeta(
    "ecs_primary_rollout_health", "Primary ECS rollout failed", Pillar.OPERATIONAL_EXCELLENCE,
    Severity.HIGH, "AWS::ECS::Service", Scope.REGIONAL,
    "Review ECS service deployment events and task or target health, then verify that a replacement rollout completes.",
)


def run(ctx):
    for arn, service in ecs_rolling_services(ctx):
        deployments = (service or {}).get("deployments", [])
        primary = next((item for item in deployments if item.get("status") == "PRIMARY"), {})
        state = primary.get("rolloutState")
        if state == "FAILED":
            yield ctx.finding(META, Status.FAIL, arn, "ECS reports that the primary rollout failed.")
        elif state == "COMPLETED":
            yield ctx.finding(META, Status.PASS, arn, "ECS reports that the primary rollout completed.")
        else:
            yield ctx.finding(META, Status.UNKNOWN, arn, "ECS did not report a completed or failed primary rollout.")

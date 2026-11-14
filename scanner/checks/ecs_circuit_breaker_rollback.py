"""Check rollback configuration for ECS rolling deployments."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import ecs_rolling_services

V2_ONLY = True
REGISTRY = {
    "service": "ecs",
    "required_actions": ["ecs:ListClusters", "ecs:ListServices", "ecs:DescribeServices"],
    "applicability": "Active ECS-controlled rolling replica services with desired tasks",
    "evidence_fields": ["deploymentConfiguration.deploymentCircuitBreaker", "deploymentConfiguration.alarms"],
    "references": ["https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-failure-detection.html"],
}
META = CheckMeta(
    "ecs_circuit_breaker_rollback", "ECS rolling service has no automatic deployment rollback",
    Pillar.OPERATIONAL_EXCELLENCE, Severity.MEDIUM, "AWS::ECS::Service", Scope.REGIONAL,
    "Review automatic rollback settings. Configure the deployment circuit breaker or CloudWatch alarm rollback when appropriate.",
)


def run(ctx):
    for arn, service in ecs_rolling_services(ctx):
        if service is None:
            yield ctx.finding(META, Status.UNKNOWN, arn, "ECS listed this service but did not return its deployment settings.")
            continue
        config = service.get("deploymentConfiguration")
        if config is None:
            yield ctx.finding(META, Status.UNKNOWN, arn, "ECS did not return deployment settings.")
            continue
        rollback = any(config.get(source, {}).get("enable") is True and config.get(source, {}).get("rollback") is True
                       for source in ("deploymentCircuitBreaker", "alarms"))
        description = "Automatic rollback is enabled." if rollback else "Neither ECS circuit breaker nor alarm rollback is enabled."
        yield ctx.finding(META, Status.PASS if rollback else Status.FAIL, arn, description)

"""Small metadata-only collectors shared by operational checks."""

from collections.abc import Iterator
from itertools import batched
from typing import Any

from scanner.check import CheckContext


def rows(client: Any, operation: str, key: str, **params: Any) -> Iterator[dict[str, Any]]:
    for page in client.get_paginator(operation).paginate(**params):
        yield from page[key]


def ecs_rolling_services(ctx: CheckContext) -> Iterator[tuple[str, dict[str, Any] | None]]:
    """Collect ECS-controlled rolling services and preserve missing descriptions."""
    ecs = ctx.client("ecs")
    for page in ecs.get_paginator("list_clusters").paginate():
        for cluster in page["clusterArns"]:
            for services in ecs.get_paginator("list_services").paginate(cluster=cluster):
                for group in batched(services["serviceArns"], 10):
                    response = ecs.describe_services(cluster=cluster, services=list(group))
                    returned = {service["serviceArn"]: service for service in response["services"]}
                    for arn in group:
                        service = returned.get(arn)
                        if service is None:
                            yield arn, None
                        elif (
                            service.get("status") == "ACTIVE"
                            and service.get("deploymentController", {}).get("type") == "ECS"
                            and service.get("deploymentConfiguration", {}).get("strategy", "ROLLING") == "ROLLING"
                            and service.get("schedulingStrategy") == "REPLICA"
                            and service.get("desiredCount", 0) > 0
                        ):
                            yield arn, service


def opted_in_instances(ctx: CheckContext, tag: str) -> Iterator[str]:
    """Scope maintenance checks to running instances explicitly tagged for it."""
    ec2 = ctx.client("ec2")
    filters = [
        {"Name": "instance-state-name", "Values": ["running"]},
        {"Name": f"tag:{tag}", "Values": ["true"]},
    ]
    for reservation in rows(ec2, "describe_instances", "Reservations", Filters=filters):
        for instance in reservation["Instances"]:
            yield instance["InstanceId"]

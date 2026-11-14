"""Read-only inventory for metric targets."""

from __future__ import annotations

from collections import defaultdict

from scanner.efficiency_metrics import Target


def instances(ctx, state: str):
    client = ctx.client("ec2")
    for page in client.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": [state]}],
    ):
        for reservation in page["Reservations"]:
            yield from reservation["Instances"]


def rds_instances(ctx):
    client = ctx.client("rds")
    for page in client.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            if db.get("DBInstanceStatus") == "available":
                yield db


def rds_targets(ctx):
    for db in rds_instances(ctx):
        yield Target(db["DBInstanceArn"], (("DBInstanceIdentifier", db["DBInstanceIdentifier"]),))


def lambda_functions(ctx, *, all_versions=False):
    client = ctx.client("lambda")
    params = {"FunctionVersion": "ALL"} if all_versions else {}
    for page in client.get_paginator("list_functions").paginate(**params):
        yield from page["Functions"]


def lambda_timeout_targets(ctx):
    timeouts = defaultdict(set)
    for function in lambda_functions(ctx, all_versions=True):
        arn = ":".join(function["FunctionArn"].split(":")[:7])
        timeouts[(arn, function["FunctionName"])].add(function.get("Timeout"))
    for (arn, name), values in timeouts.items():
        timeout = next(iter(values)) if len(values) == 1 else None
        yield Target(arn, (("FunctionName", name),), timeout)


def dynamodb_tables(ctx):
    client = ctx.client("dynamodb")
    for page in client.get_paginator("list_tables").paginate():
        for table in page["TableNames"]:
            yield Target(ctx.arn("dynamodb", f"table/{table}"), (("TableName", table),))


def ecs_services(ctx):
    ecs = ctx.client("ecs")
    for cluster_page in ecs.get_paginator("list_clusters").paginate():
        for cluster_arn in cluster_page["clusterArns"]:
            for service_page in ecs.get_paginator("list_services").paginate(cluster=cluster_arn):
                services = service_page["serviceArns"]
                if not services:
                    continue
                # DescribeServices accepts up to ten services per call.
                for offset in range(0, len(services), 10):
                    result = ecs.describe_services(cluster=cluster_arn, services=services[offset:offset + 10])
                    if result.get("failures"):
                        raise ValueError("ECS returned incomplete service inventory")
                    for service in result["services"]:
                        if service.get("status") != "ACTIVE" or service.get("runningCount", 0) == 0:
                            continue
                        yield Target(service["serviceArn"], (
                            ("ClusterName", cluster_arn.rsplit("/", 1)[-1]),
                            ("ServiceName", service["serviceName"]),
                        ))

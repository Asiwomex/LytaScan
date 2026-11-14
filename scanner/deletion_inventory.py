"""Bounded, read-only inventories used to confirm resource removal."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from hashlib import sha256
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from scanner.check import GLOBAL_ENDPOINT_REGION, GLOBAL_REGION

MAX_RESOURCES = 2000
MAX_PAGES = 100
INVENTORY_CONFIG = Config(connect_timeout=2, read_timeout=4, retries={"total_max_attempts": 2, "mode": "standard"})
_client_lock = Lock()


@dataclass(frozen=True)
class InventorySpec:
    service: str
    operation: str
    result_key: str
    arn_pattern: str
    id_key: str | None = None
    global_scope: bool = False
    parameters: dict[str, Any] = field(default_factory=dict)


INVENTORY = {
    "AWS::EC2::Instance": InventorySpec("ec2", "describe_instances", "Reservations", "ec2:{region}:{account}:instance/*", "InstanceId"),
    "AWS::EC2::Volume": InventorySpec("ec2", "describe_volumes", "Volumes", "ec2:{region}:{account}:volume/*", "VolumeId"),
    "AWS::EC2::SecurityGroup": InventorySpec("ec2", "describe_security_groups", "SecurityGroups", "ec2:{region}:{account}:security-group/*", "GroupId"),
    "AWS::EC2::Snapshot": InventorySpec("ec2", "describe_snapshots", "Snapshots", "ec2:{region}::snapshot/*", "SnapshotId", parameters={"OwnerIds": ["self"]}),
    "AWS::EC2::EIP": InventorySpec("ec2", "describe_addresses", "Addresses", "ec2:{region}:{account}:elastic-ip/*", "AllocationId"),
    "AWS::DynamoDB::Table": InventorySpec("dynamodb", "list_tables", "TableNames", "dynamodb:{region}:{account}:table/*"),
    "AWS::RDS::DBInstance": InventorySpec("rds", "describe_db_instances", "DBInstances", "rds:{region}:{account}:db:*", "DBInstanceArn"),
    "AWS::S3::Bucket": InventorySpec("s3", "list_buckets", "Buckets", "s3:::*", "Name", global_scope=True),
    "AWS::IAM::User": InventorySpec("iam", "list_users", "Users", "iam::{account}:user/*", "Arn", global_scope=True),
    "AWS::IAM::AccessKey": InventorySpec("iam", "list_users", "Users", "iam::{account}:user/*", global_scope=True),
    "AWS::IAM::ManagedPolicy": InventorySpec("iam", "list_policies", "Policies", "iam::{account}:policy/*", "Arn", global_scope=True, parameters={"Scope": "Local"}),
    "AWS::Lambda::Function": InventorySpec("lambda", "list_functions", "Functions", "lambda:{region}:{account}:function:*", "FunctionArn"),
    "AWS::Logs::LogGroup": InventorySpec("logs", "describe_log_groups", "logGroups", "logs:{region}:{account}:log-group:*", "arn"),
    "AWS::AutoScaling::AutoScalingGroup": InventorySpec("autoscaling", "describe_auto_scaling_groups", "AutoScalingGroups", "autoscaling:{region}:{account}:autoScalingGroup:*", "AutoScalingGroupARN"),
    "AWS::ElasticLoadBalancingV2::LoadBalancer": InventorySpec("elbv2", "describe_load_balancers", "LoadBalancers", "elasticloadbalancing:{region}:{account}:loadbalancer/*", "LoadBalancerArn"),
    "AWS::ElasticLoadBalancingV2::TargetGroup": InventorySpec("elbv2", "describe_target_groups", "TargetGroups", "elasticloadbalancing:{region}:{account}:targetgroup/*", "TargetGroupArn"),
    "AWS::ECR::Repository": InventorySpec("ecr", "describe_repositories", "repositories", "ecr:{region}:{account}:repository/*", "repositoryArn"),
    "AWS::EFS::FileSystem": InventorySpec("efs", "describe_file_systems", "FileSystems", "elasticfilesystem:{region}:{account}:file-system/*", "FileSystemId"),
    "AWS::CloudWatch::Alarm": InventorySpec("cloudwatch", "describe_alarms", "MetricAlarms", "cloudwatch:{region}:{account}:alarm:*", "AlarmArn"),
    "AWS::CloudFormation::Stack": InventorySpec("cloudformation", "list_stacks", "StackSummaries", "cloudformation:{region}:{account}:stack/*", "StackId"),
    "AWS::CloudTrail::Trail": InventorySpec("cloudtrail", "describe_trails", "trailList", "cloudtrail:{region}:{account}:trail/*", "TrailARN", parameters={"includeShadowTrails": False}),
    "AWS::CodePipeline::Pipeline": InventorySpec("codepipeline", "list_pipelines", "pipelines", "codepipeline:{region}:{account}:*", "name"),
    "AWS::Config::ConfigurationRecorder": InventorySpec("config", "describe_configuration_recorder_status", "ConfigurationRecordersStatus", "config:{region}:{account}:configuration-recorder/*", "name"),
    "AWS::Config::DeliveryChannel": InventorySpec("config", "describe_delivery_channel_status", "DeliveryChannelsStatus", "config:{region}:{account}:delivery-channel/*", "name"),
    "AWS::SQS::Queue": InventorySpec("sqs", "list_queues", "QueueUrls", "sqs:{region}:{account}:*"),
    "AWS::StepFunctions::StateMachine": InventorySpec("stepfunctions", "list_state_machines", "stateMachines", "states:{region}:{account}:stateMachine:*", "stateMachineArn"),
    "AWS::ECS::Service": InventorySpec("ecs", "list_clusters", "clusterArns", "ecs:{region}:{account}:service/*"),
    "AWS::ApiGateway::Stage": InventorySpec("apigateway", "get_rest_apis", "items", "apigateway:{region}::/restapis/*"),
    "AWS::ApiGatewayV2::Stage": InventorySpec("apigatewayv2", "get_apis", "Items", "apigateway:{region}::/apis/*"),
}


def _arn_prefix(spec: InventorySpec, account_id: str, region: str) -> str:
    return "arn:aws:" + spec.arn_pattern.removesuffix("*").format(account=account_id, region=region)


def inventory_region(resource_type: str, report_region: str) -> str | None:
    spec = INVENTORY.get(resource_type)
    if not spec:
        return None
    return GLOBAL_REGION if spec.global_scope else report_region


def valid_identity(resource_type: str, account_id: str, region: str, arn: str) -> bool:
    spec = INVENTORY.get(resource_type)
    if not spec or (region == GLOBAL_REGION) != spec.global_scope:
        return False
    prefix = _arn_prefix(spec, account_id, region)
    suffix = arn.removeprefix(prefix)
    if not arn.startswith(prefix) or not suffix or arn.endswith(":root") or any(char.isspace() for char in arn):
        return False
    if resource_type in ("AWS::ApiGateway::Stage", "AWS::ApiGatewayV2::Stage"):
        return "/stages/" in suffix
    if resource_type == "AWS::IAM::AccessKey":
        owner, separator, key = suffix.rpartition("/access-key/")
        return bool(owner and separator and len(key) == 64 and all(char in "0123456789abcdef" for char in key))
    return True


def _rows(client, operation, result_key, should_continue, *, pagination_required=False, **parameters):
    if not should_continue():
        raise InventoryInterrupted
    if client.can_paginate(operation):
        pages = client.get_paginator(operation).paginate(**parameters)
    elif not pagination_required:
        pages = [getattr(client, operation)(**parameters)]
    else:
        raise ValueError("Pagination unavailable")
    pages = iter(pages)
    for index in range(MAX_PAGES + 1):
        if not should_continue():
            raise InventoryInterrupted
        try:
            page = next(pages)
        except StopIteration:
            return
        if index == MAX_PAGES:
            raise InventoryLimit
        rows = page.get(result_key)
        if not isinstance(rows, list):
            # S3 and SQS may omit their optional collection on an empty response.
            if result_key in ("Buckets", "QueueUrls") and result_key not in page:
                rows = []
            else:
                raise ValueError("Inventory response omitted its resource list")
        yield from rows


class InventoryLimit(Exception):
    pass


class InventoryInterrupted(Exception):
    pass


def _identifiers(client, resource_type, spec, account_id, region, should_continue) -> Iterator[str]:
    prefix = _arn_prefix(spec, account_id, region)
    params = dict(spec.parameters)
    if resource_type == "AWS::SQS::Queue":
        # The API only returns a continuation token when MaxResults is set.
        params["PaginationConfig"] = {"PageSize": 1000}
    rows = _rows(client, spec.operation, spec.result_key, should_continue,
                 pagination_required=resource_type in ("AWS::S3::Bucket", "AWS::SQS::Queue"), **params)
    if resource_type == "AWS::ECS::Service":
        for cluster in rows:
            yield from _rows(client, "list_services", "serviceArns", should_continue, cluster=cluster)
        return
    if resource_type == "AWS::IAM::AccessKey":
        for user in rows:
            for key in _rows(client, "list_access_keys", "AccessKeyMetadata", should_continue, UserName=user["UserName"]):
                digest = sha256(key["AccessKeyId"].encode()).hexdigest()
                yield f"{user['Arn']}/access-key/{digest}"
        return
    if resource_type in ("AWS::ApiGateway::Stage", "AWS::ApiGatewayV2::Stage"):
        v2 = resource_type == "AWS::ApiGatewayV2::Stage"
        for api in rows:
            api_id = api["ApiId" if v2 else "id"]
            bindings = {"ApiId": api_id} if v2 else {"restApiId": api_id}
            for stage in _rows(client, "get_stages", "Items" if v2 else "item", should_continue, **bindings):
                yield f"{prefix}{api_id}/stages/{stage['StageName' if v2 else 'stageName']}"
        return

    if resource_type == "AWS::EC2::Instance":
        rows = (instance for reservation in rows for instance in reservation["Instances"])
    for row in rows:
        if resource_type == "AWS::CloudFormation::Stack" and row.get("StackStatus") == "DELETE_COMPLETE":
            continue
        if resource_type == "AWS::CloudTrail::Trail" and row["HomeRegion"] != region:
            continue
        if resource_type == "AWS::EC2::EIP" and not row.get("AllocationId") and row.get("Domain") == "standard":
            # Legacy EC2-Classic addresses have no corresponding finding identity.
            continue
        value = row[spec.id_key] if spec.id_key else row
        if resource_type == "AWS::SQS::Queue":
            url_parts = urlsplit(value).path.strip("/").split("/")
            if len(url_parts) != 2 or url_parts[0] != account_id:
                raise ValueError("Queue inventory returned an unexpected account")
            value = url_parts[1]
        if not isinstance(value, str) or not value:
            raise ValueError("Inventory response omitted a resource identity")
        yield value if value.startswith("arn:") else prefix + value
        if resource_type == "AWS::Config::ConfigurationRecorder" and row.get("arn"):
            yield row["arn"]


def _collect_scope(session, spec, resource_type, account_id, region, should_continue):
    scope = {
        "resource_type": resource_type, "region": region, "account_id": account_id,
        "complete": False, "resource_ids": [],
    }
    if not should_continue():
        return {**scope, "reason_code": "interrupted"}
    try:
        endpoint = GLOBAL_ENDPOINT_REGION if region == GLOBAL_REGION else region
        with _client_lock:
            client = session.client(spec.service, region_name=endpoint, config=INVENTORY_CONFIG)
        ids = set()
        for index, raw in enumerate(_identifiers(client, resource_type, spec, account_id, region, should_continue)):
            if index >= MAX_RESOURCES:
                raise InventoryLimit
            arn = raw.strip().removesuffix(":*")
            if not valid_identity(resource_type, account_id, region, arn):
                raise ValueError("Inventory resource has an unexpected identity")
            ids.add(arn)
    except InventoryLimit:
        return {**scope, "reason_code": "inventory_limit"}
    except InventoryInterrupted:
        return {**scope, "reason_code": "interrupted"}
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        reason = "permission_denied" if "denied" in code.lower() or code == "UnauthorizedOperation" else "inventory_unavailable"
        return {**scope, "reason_code": reason}
    except (BotoCoreError, KeyError, ValueError, TypeError, AttributeError):
        return {**scope, "reason_code": "inventory_unavailable"}
    if not should_continue():
        return {**scope, "reason_code": "interrupted"}
    return {**scope, "complete": True, "resource_ids": sorted(ids)}


def collect_inventory(
    session: Any, account_id: str, region: str, *,
    resource_types: set[str] | None = None,
    should_continue: Callable[[], bool] = lambda: True,
) -> list[dict[str, Any]]:
    """List whole resource types in the authenticated account and selected region."""
    scopes = [(resource_type, spec) for resource_type, spec in INVENTORY.items()
              if resource_types is None or resource_type in resource_types]
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(
            lambda item: _collect_scope(session, item[1], item[0], account_id,
                                        GLOBAL_REGION if item[1].global_scope else region, should_continue),
            scopes,
        ))

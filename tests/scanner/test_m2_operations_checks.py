from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest
import boto3
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from scanner.check import CheckContext
from scanner.checks import (
    apigateway_http_access_logs,
    apigateway_rest_access_logs,
    backup_latest_job_health,
    cloudformation_rollback_health,
    codepipeline_latest_execution,
    config_delivery_channel_health,
    config_recorder_running,
    ec2_ssm_managed,
    ec2_ssm_patch_compliance,
    ecs_circuit_breaker_rollback,
    ecs_primary_rollout_health,
    stepfunctions_express_logging,
)
from scanner.engine import Check, run_check
from scanner.findings import Status

ACCOUNT = "111122223333"
REGION = "us-east-1"
NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


@pytest.fixture
def clients():
    return {}


@pytest.fixture
def ctx(clients):
    session = Mock()
    session.client.side_effect = lambda service, **_: clients.setdefault(service, Mock())
    return CheckContext(session, ACCOUNT, REGION, NOW)


def pages(client, values):
    client.get_paginator.side_effect = lambda operation: Mock(paginate=Mock(return_value=values[operation]))


def statuses(check, ctx):
    return [finding.status for finding in check.run(ctx)]


@pytest.mark.parametrize("recording, expected", [
    (True, Status.PASS), (False, Status.FAIL), (None, Status.UNKNOWN),
])
def test_existing_config_recorder(ctx, recording, expected):
    config = ctx.client("config")
    record = {"name": "customer"}
    if recording is not None:
        record["recording"] = recording
    config.describe_configuration_recorder_status.return_value = {"ConfigurationRecordersStatus": [
        {"name": "linked", "servicePrincipal": "backup.amazonaws.com", "recording": False}, record,
    ]}
    assert statuses(config_recorder_running, ctx) == [expected]
    config.describe_configuration_recorder_status.return_value = {"ConfigurationRecordersStatus": []}
    assert statuses(config_recorder_running, ctx) == []


@pytest.mark.parametrize("snapshot, history, expected", [
    ("Success", "Success", Status.PASS),
    ("Not_Applicable", "Success", Status.PASS),
    ("Success", "Failure", Status.FAIL),
    (None, "Not_Applicable", Status.UNKNOWN),
])
def test_config_latest_deliveries(ctx, snapshot, history, expected):
    config = ctx.client("config")
    config.describe_delivery_channel_status.return_value = {"DeliveryChannelsStatus": [{
        "name": "default", "configSnapshotDeliveryInfo": {"lastStatus": snapshot},
        "configHistoryDeliveryInfo": {"lastStatus": history},
    }]}
    assert statuses(config_delivery_channel_health, ctx) == [expected]
    config.describe_delivery_channel_status.return_value = {"DeliveryChannelsStatus": []}
    assert statuses(config_delivery_channel_health, ctx) == []


def test_codepipeline_does_not_count_running_or_empty_history_as_pass(ctx):
    pipeline = ctx.client("codepipeline")
    pages(pipeline, {"list_pipelines": [
        {"pipelines": [{"name": "ok"}, {"name": "broken"}]},
        {"pipelines": [{"name": "running"}, {"name": "new"}]},
    ]})
    outcomes = {"ok": "Succeeded", "broken": "Failed", "running": "InProgress", "new": None}
    pipeline.list_pipeline_executions.side_effect = lambda pipelineName, maxResults: {
        "pipelineExecutionSummaries": [{"status": outcomes[pipelineName]}] if outcomes[pipelineName] else [],
    }
    assert statuses(codepipeline_latest_execution, ctx) == [Status.PASS, Status.FAIL, Status.UNKNOWN, Status.UNKNOWN]
    assert all(call.kwargs["maxResults"] == 1 for call in pipeline.list_pipeline_executions.call_args_list)


def test_backup_paginates_and_evaluates_latest_terminal_job_for_each_resource(ctx):
    backup = ctx.client("backup")
    paginator = backup.get_paginator.return_value
    paginator.paginate.return_value = [
        {"BackupJobs": [
            {"ResourceArn": "arn:old-fail", "CreationDate": NOW - timedelta(days=3), "State": "FAILED"},
            {"ResourceArn": "arn:partial", "CreationDate": NOW, "State": "PARTIAL"},
            {"ResourceArn": "arn:in-progress", "CreationDate": NOW, "State": "RUNNING"},
        ]},
        {"BackupJobs": [
            {"ResourceArn": "arn:old-fail", "CreationDate": NOW, "State": "COMPLETED", "MessageCategory": "SUCCESS"},
            {"ResourceArn": "arn:with-issues", "CreationDate": NOW, "State": "COMPLETED", "MessageCategory": "OTHER"},
            {"ResourceArn": "arn:no-category", "CreationDate": NOW, "State": "COMPLETED"},
            {"State": "EXPIRED"},
        ]},
    ]
    assert {finding.resource_arn: finding.status for finding in backup_latest_job_health.run(ctx)} == {
        "arn:old-fail": Status.PASS, "arn:partial": Status.FAIL, "arn:with-issues": Status.FAIL,
        "arn:no-category": Status.UNKNOWN, ctx.account_arn: Status.UNKNOWN,
    }
    paginator.paginate.assert_called_once_with(ByAccountId=ACCOUNT, ByCreatedAfter=NOW - timedelta(days=7))


def test_ecs_rolling_service_rules_assess_independent_signals(ctx):
    ecs = ctx.client("ecs")
    services = [
        ("breaker", {"deploymentCircuitBreaker": {"enable": True, "rollback": True}}, "FAILED"),
        ("alarm", {"alarms": {"enable": True, "rollback": True}}, "COMPLETED"),
        ("no-rollback", {"deploymentCircuitBreaker": {"enable": True, "rollback": False}}, "IN_PROGRESS"),
        ("missing-config", None, None),
        ("blue-green", {"strategy": "BLUE_GREEN"}, "FAILED"),
    ]
    pages(ecs, {
        "list_clusters": [{"clusterArns": ["cluster"]}],
        "list_services": [{"serviceArns": [name for name, _, _ in services] + ["missing-describe"]}],
    })
    ecs.describe_services.return_value = {"services": [
        {
            "serviceArn": name, "status": "ACTIVE", "deploymentController": {"type": "ECS"},
            "schedulingStrategy": "REPLICA", "desiredCount": 1,
            "deployments": [{"status": "PRIMARY", "rolloutState": state}],
            **({"deploymentConfiguration": config} if config is not None else {}),
        } for name, config, state in services
    ], "failures": [{"arn": "missing-describe", "reason": "MISSING"}]}
    assert statuses(ecs_circuit_breaker_rollback, ctx) == [
        Status.PASS, Status.PASS, Status.FAIL, Status.UNKNOWN, Status.UNKNOWN,
    ]
    assert statuses(ecs_primary_rollout_health, ctx) == [
        Status.FAIL, Status.PASS, Status.UNKNOWN, Status.UNKNOWN, Status.UNKNOWN,
    ]


def test_http_api_access_logs_exclude_websocket_and_undeployed_stages(ctx):
    gateway = ctx.client("apigatewayv2")
    pages(gateway, {
        "get_apis": [{"Items": [{"ApiId": "ws", "ProtocolType": "WEBSOCKET"}, {"ApiId": "http", "ProtocolType": "HTTP"}]}],
        "get_stages": [{"Items": [
            {"StageName": "live", "DeploymentId": "d1", "AccessLogSettings": {"DestinationArn": "log", "Format": "$context.requestId"}},
            {"StageName": "unlogged", "DeploymentId": "d2"},
            {"StageName": "undeployed"},
        ]}],
    })
    assert statuses(apigateway_http_access_logs, ctx) == [Status.PASS, Status.FAIL]


def test_rest_api_access_logs_exclude_undeployed_stages(ctx):
    gateway = ctx.client("apigateway")
    pages(gateway, {"get_rest_apis": [{"items": [{"id": "rest"}]}]})
    gateway.get_stages.return_value = {"item": [
        {"stageName": "live", "deploymentId": "d1", "accessLogSettings": {"destinationArn": "log", "format": "$context.requestId"}},
        {"stageName": "unlogged", "deploymentId": "d2"},
        {"stageName": "undeployed"},
    ]}
    assert statuses(apigateway_rest_access_logs, ctx) == [Status.PASS, Status.FAIL]
    gateway.get_stages.assert_called_once_with(restApiId="rest")


def test_express_logging_uses_metadata_only_and_excludes_standard_workflows(ctx):
    sf = ctx.client("stepfunctions")
    machines = ["logged", "off", "unknown", "deleting", "standard"]
    pages(sf, {"list_state_machines": [{"stateMachines": [
        {"stateMachineArn": name, "type": "STANDARD" if name == "standard" else "EXPRESS"}
        for name in machines
    ]}]})
    details = {
        "logged": {"loggingConfiguration": {"level": "ERROR", "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": "logs"}}]}},
        "off": {"loggingConfiguration": {"level": "OFF"}},
        "unknown": {},
        "deleting": {"status": "DELETING"},
    }
    sf.describe_state_machine.side_effect = lambda stateMachineArn, includedData: details[stateMachineArn]
    assert statuses(stepfunctions_express_logging, ctx) == [Status.PASS, Status.FAIL, Status.UNKNOWN]
    assert [call.kwargs for call in sf.describe_state_machine.call_args_list] == [
        {"stateMachineArn": machine, "includedData": "METADATA_ONLY"} for machine in machines[:-1]
    ]


def test_cloudformation_handles_failed_rollback_pending_and_deleted_stacks(ctx):
    cloudformation = ctx.client("cloudformation")
    states = ["UPDATE_ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "UPDATE_IN_PROGRESS", "DELETE_COMPLETE"]
    pages(cloudformation, {"list_stacks": [{"StackSummaries": [
        {"StackId": f"stack-{index}", "StackStatus": state} for index, state in enumerate(states)
    ]}]})
    assert statuses(cloudformation_rollback_health, ctx) == [Status.FAIL, Status.PASS, Status.UNKNOWN]


def ec2_inventory(ctx, ids):
    ec2 = ctx.client("ec2")
    paginator = ec2.get_paginator.return_value
    paginator.paginate.return_value = [{"Reservations": [
        {"Instances": [{"InstanceId": instance} for instance in ids]},
    ]}]
    return paginator


def test_ssm_management_checks_only_opted_in_running_instances(ctx):
    inventory = ec2_inventory(ctx, ["i-01", "i-02", "i-03", "i-04"])
    ssm = ctx.client("ssm")
    pages(ssm, {"describe_instance_information": [{"InstanceInformationList": [
        {"InstanceId": "i-01", "PingStatus": "Online"},
        {"InstanceId": "i-02", "PingStatus": "ConnectionLost"},
        {"InstanceId": "i-04"},
        {"InstanceId": "i-unselected", "PingStatus": "ConnectionLost"},
    ]}]})
    assert statuses(ec2_ssm_managed, ctx) == [Status.PASS, Status.FAIL, Status.FAIL, Status.UNKNOWN]
    inventory.paginate.assert_called_once_with(Filters=[
        {"Name": "instance-state-name", "Values": ["running"]},
        {"Name": "tag:pillarscan:ssm-managed", "Values": ["true"]},
    ])


def test_ssm_patch_checks_require_current_complete_baseline(ctx):
    inventory = ec2_inventory(ctx, ["i-01", "i-02", "i-03", "i-04", "i-05"])
    ssm = ctx.client("ssm")
    common = {"OperationEndTime": NOW, "MissingCount": 0, "FailedCount": 0, "InstalledPendingRebootCount": 0}
    pages(ssm, {"describe_instance_patch_states": [{"InstancePatchStates": [
        {"InstanceId": "i-01", **common},
        {"InstanceId": "i-02", **common, "InstalledPendingRebootCount": 1},
        {"InstanceId": "i-03", **common, "OperationEndTime": NOW - timedelta(days=15)},
        {"InstanceId": "i-04", "OperationEndTime": NOW},
    ]}]})
    assert statuses(ec2_ssm_patch_compliance, ctx) == [
        Status.PASS, Status.FAIL, Status.UNKNOWN, Status.UNKNOWN, Status.UNKNOWN,
    ]
    inventory.paginate.assert_called_once_with(Filters=[
        {"Name": "instance-state-name", "Values": ["running"]},
        {"Name": "tag:pillarscan:ssm-patched", "Values": ["true"]},
    ])


@pytest.mark.parametrize("check", [
    apigateway_http_access_logs, apigateway_rest_access_logs, backup_latest_job_health,
    cloudformation_rollback_health, codepipeline_latest_execution, config_delivery_channel_health,
    config_recorder_running, ec2_ssm_managed, ec2_ssm_patch_compliance, ecs_circuit_breaker_rollback,
    ecs_primary_rollout_health, stepfunctions_express_logging,
])
def test_read_permission_denial_does_not_pass(check, ctx):
    ctx.session.client.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "MockRead")
    findings = run_check(Check(check.META, check.run), ctx)
    assert [item.status for item in findings] == [Status.ERROR]


@pytest.mark.parametrize(("check", "service", "operation", "response", "params"), [
    (apigateway_http_access_logs, "apigatewayv2", "get_apis", {"Items": []}, {}),
    (apigateway_rest_access_logs, "apigateway", "get_rest_apis", {"items": []}, {}),
    (backup_latest_job_health, "backup", "list_backup_jobs", {"BackupJobs": []},
     {"ByAccountId": ACCOUNT, "ByCreatedAfter": NOW - timedelta(days=7)}),
    (cloudformation_rollback_health, "cloudformation", "list_stacks", {"StackSummaries": []}, {}),
    (codepipeline_latest_execution, "codepipeline", "list_pipelines", {"pipelines": []}, {}),
    (config_delivery_channel_health, "config", "describe_delivery_channel_status", {"DeliveryChannelsStatus": []}, {}),
    (config_recorder_running, "config", "describe_configuration_recorder_status", {"ConfigurationRecordersStatus": []}, {}),
    (ec2_ssm_managed, "ec2", "describe_instances", {"Reservations": []}, {"Filters": [
        {"Name": "instance-state-name", "Values": ["running"]},
        {"Name": "tag:pillarscan:ssm-managed", "Values": ["true"]},
    ]}),
    (ec2_ssm_patch_compliance, "ec2", "describe_instances", {"Reservations": []}, {"Filters": [
        {"Name": "instance-state-name", "Values": ["running"]},
        {"Name": "tag:pillarscan:ssm-patched", "Values": ["true"]},
    ]}),
    (ecs_circuit_breaker_rollback, "ecs", "list_clusters", {"clusterArns": []}, {}),
    (ecs_primary_rollout_health, "ecs", "list_clusters", {"clusterArns": []}, {}),
    (stepfunctions_express_logging, "stepfunctions", "list_state_machines", {"stateMachines": []}, {}),
])
def test_empty_inventory_matches_aws_sdk_contract(check, service, operation, response, params, ctx):
    client = boto3.client(service, aws_access_key_id="stub", aws_secret_access_key="stub", region_name=REGION)
    with Stubber(client) as stub:
        stub.add_response(operation, response, expected_params=params)
        ctx.session.client.return_value = client
        ctx.session.client.side_effect = None
        assert list(check.run(ctx)) == []
        stub.assert_no_pending_responses()

"""Check execution logging for active Step Functions Express workflows."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import rows

V2_ONLY = True
REGISTRY = {
    "service": "stepfunctions",
    "required_actions": ["states:ListStateMachines", "states:DescribeStateMachine"],
    "applicability": "Active Step Functions Express workflows",
    "evidence_fields": ["type", "status", "loggingConfiguration.level", "loggingConfiguration.destinations"],
    "references": ["https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html",
                   "https://docs.aws.amazon.com/step-functions/latest/apireference/API_DescribeStateMachine.html"],
}
META = CheckMeta(
    "stepfunctions_express_logging", "Step Functions Express workflow execution logs not configured",
    Pillar.OPERATIONAL_EXCELLENCE, Severity.MEDIUM, "AWS::StepFunctions::StateMachine", Scope.REGIONAL,
    "Configure an approved CloudWatch Logs destination at an appropriate level. Exclude execution data when it may be sensitive.",
)


def run(ctx):
    stepfunctions = ctx.client("stepfunctions")
    for machine in rows(stepfunctions, "list_state_machines", "stateMachines"):
        if machine.get("type") != "EXPRESS":
            continue
        arn = machine["stateMachineArn"]
        details = stepfunctions.describe_state_machine(stateMachineArn=arn, includedData="METADATA_ONLY")
        if details.get("status") == "DELETING":
            continue
        logs = details.get("loggingConfiguration", {})
        level = logs.get("level")
        if level not in ("OFF", "ALL", "ERROR", "FATAL"):
            yield ctx.finding(META, Status.UNKNOWN, arn, "Step Functions did not return the workflow's log level.")
            continue
        enabled = level != "OFF" and any(
            item.get("cloudWatchLogsLogGroup", {}).get("logGroupArn") for item in logs.get("destinations", [])
        )
        description = "Express workflow execution logging is configured." if enabled else "Express workflow execution logging is not configured."
        yield ctx.finding(META, Status.PASS if enabled else Status.FAIL, arn, description)

"""Find CloudFormation stacks whose rollback failed."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import rows

V2_ONLY = True
REGISTRY = {
    "service": "cloudformation",
    "required_actions": ["cloudformation:ListStacks"],
    "applicability": "Existing CloudFormation stacks",
    "evidence_fields": ["StackStatus"],
    "references": ["https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackSummary.html",
                   "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-continueupdaterollback.html"],
}
META = CheckMeta(
    "cloudformation_rollback_health", "CloudFormation stack rollback failed", Pillar.OPERATIONAL_EXCELLENCE,
    Severity.HIGH, "AWS::CloudFormation::Stack", Scope.REGIONAL,
    "Review CloudFormation stack events and address the blocked resource. Follow AWS recovery guidance before continuing the rollback.",
)


def run(ctx):
    cloudformation = ctx.client("cloudformation")
    for stack in rows(cloudformation, "list_stacks", "StackSummaries"):
        state = stack.get("StackStatus")
        if state == "DELETE_COMPLETE":
            continue
        arn = stack.get("StackId")
        if not arn:
            yield ctx.finding(META, Status.UNKNOWN, ctx.account_arn, "CloudFormation did not return a stack identifier.")
            continue
        if state in ("ROLLBACK_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_ROLLBACK_FAILED"):
            yield ctx.finding(META, Status.FAIL, arn, "The stack is in a failed rollback state.")
        elif state is None or not (state.endswith("_COMPLETE") or state.endswith("_FAILED")):
            yield ctx.finding(META, Status.UNKNOWN, arn, "The stack has no stable rollback status.")
        else:
            yield ctx.finding(META, Status.PASS, arn, "The stack is not in a failed rollback state.")

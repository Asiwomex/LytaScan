"""Check recent patch baseline results only for instances opted in to patching."""

from datetime import timedelta
from itertools import batched

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import opted_in_instances, rows

V2_ONLY = True
PATCH_TAG = "pillarscan:ssm-patched"
REGISTRY = {
    "service": "ssm",
    "required_actions": ["ec2:DescribeInstances", "ssm:DescribeInstancePatchStates"],
    "applicability": f"Running EC2 instances tagged {PATCH_TAG}=true; patch evidence is current for 14 days",
    "evidence_fields": ["InstanceId", "OperationEndTime", "MissingCount", "FailedCount", "InstalledPendingRebootCount"],
    "references": ["https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeInstancePatchStates.html"],
}
META = CheckMeta(
    "ec2_ssm_patch_compliance", "Opted-in EC2 instance has pending or failed baseline patches",
    Pillar.OPERATIONAL_EXCELLENCE, Severity.MEDIUM, "AWS::EC2::Instance", Scope.REGIONAL,
    "Review the node's current patch baseline and failed installations. Apply approved patches or schedule a reboot when appropriate.",
)
COUNTS = ("MissingCount", "FailedCount", "InstalledPendingRebootCount")


def run(ctx):
    instances = sorted(set(opted_in_instances(ctx, PATCH_TAG)))
    if not instances:
        return
    ssm = ctx.client("ssm")
    for group in batched(instances, 50):
        observed = {
            state["InstanceId"]: state for state in rows(ssm, "describe_instance_patch_states", "InstancePatchStates", InstanceIds=list(group))
        }
        for instance in group:
            arn = ctx.arn("ec2", f"instance/{instance}")
            state = observed.get(instance, {})
            last = state.get("OperationEndTime")
            if last is None or last < ctx.now - timedelta(days=14) or last > ctx.now:
                yield ctx.finding(META, Status.UNKNOWN, arn, "No current patch operation was reported in the 14-day evidence window.")
                continue
            counts = tuple(state.get(field) for field in COUNTS)
            if any(value is None for value in counts):
                yield ctx.finding(META, Status.UNKNOWN, arn, "The current patch operation omitted baseline counts.")
                continue
            missing, failed, reboot = counts
            status = Status.FAIL if any(counts) else Status.PASS
            yield ctx.finding(META, status, arn, f"Latest patch baseline: {missing} missing, {failed} failed, {reboot} awaiting reboot.")

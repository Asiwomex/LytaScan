"""Check Systems Manager registration only for instances opted in to management."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import opted_in_instances, rows

V2_ONLY = True
MANAGEMENT_TAG = "pillarscan:ssm-managed"
REGISTRY = {
    "service": "ssm",
    "required_actions": ["ec2:DescribeInstances", "ssm:DescribeInstanceInformation"],
    "applicability": f"Running EC2 instances tagged {MANAGEMENT_TAG}=true",
    "evidence_fields": ["InstanceId", "PingStatus"],
    "references": ["https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DescribeInstanceInformation.html"],
}
META = CheckMeta(
    "ec2_ssm_managed", "Opted-in EC2 instance is not online in Systems Manager", Pillar.OPERATIONAL_EXCELLENCE,
    Severity.MEDIUM, "AWS::EC2::Instance", Scope.REGIONAL,
    "Review the SSM Agent, instance profile and connectivity to Systems Manager. Confirm the instance is online in Fleet Manager.",
)


def run(ctx):
    selected = set(opted_in_instances(ctx, MANAGEMENT_TAG))
    if not selected:
        return
    ssm = ctx.client("ssm")
    managed = {
        node["InstanceId"]: node.get("PingStatus")
        for node in rows(ssm, "describe_instance_information", "InstanceInformationList",
                         Filters=[{"Key": "ResourceType", "Values": ["EC2Instance"]}])
    }
    for instance in sorted(selected):
        arn = ctx.arn("ec2", f"instance/{instance}")
        if instance not in managed:
            yield ctx.finding(META, Status.FAIL, arn, "The running instance is opted in but absent from the managed EC2 node list.")
        elif managed[instance] == "Online":
            yield ctx.finding(META, Status.PASS, arn, "The Systems Manager node is online.")
        elif managed[instance] in ("ConnectionLost", "Inactive"):
            yield ctx.finding(META, Status.FAIL, arn, "The Systems Manager node is offline.")
        else:
            yield ctx.finding(META, Status.UNKNOWN, arn, "Systems Manager did not report a known connection state.")

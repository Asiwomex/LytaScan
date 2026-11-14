"""Check that enabled instance metadata endpoints require IMDSv2."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import items
from scanner.findings import Finding, Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "ec2_imdsv2_required", "Instance metadata endpoint allows IMDSv1",
    Pillar.SECURITY, Severity.HIGH, "AWS::EC2::Instance", Scope.REGIONAL,
    "Confirm instance applications and agents support IMDSv2, then require metadata tokens.",
)
REGISTRY = {
    "service": "ec2",
    "required_actions": ("ec2:DescribeInstances",),
    "applicability": "EC2 instances with a metadata endpoint; excludes terminating and terminated instances",
    "evidence_fields": ("MetadataOptions.HttpEndpoint", "MetadataOptions.HttpTokens", "MetadataOptions.State"),
    "references": ("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    ec2 = ctx.client("ec2")
    for reservation in items(ec2, "describe_instances", "Reservations"):
        for instance in reservation["Instances"]:
            if instance.get("State", {}).get("Name") in {"shutting-down", "terminated"}:
                continue
            arn = ctx.arn("ec2", f"instance/{instance['InstanceId']}")
            options = instance.get("MetadataOptions", {})
            endpoint, tokens = options.get("HttpEndpoint"), options.get("HttpTokens")
            if options.get("State") != "applied":
                yield ctx.finding(META, Status.UNKNOWN, arn, "The effective metadata settings are unavailable or pending.")
            elif endpoint == "disabled":
                yield ctx.finding(META, Status.PASS, arn, "The instance metadata endpoint is disabled.")
            elif endpoint == "enabled" and tokens == "required":
                yield ctx.finding(META, Status.PASS, arn, "The instance metadata endpoint requires IMDSv2 tokens.")
            elif endpoint == "enabled" and tokens == "optional":
                yield ctx.finding(META, Status.FAIL, arn, "The instance metadata endpoint accepts requests without an IMDSv2 token.")
            else:
                yield ctx.finding(META, Status.UNKNOWN, arn, "AWS did not return a recognized metadata configuration.")

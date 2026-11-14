"""Check encryption on provisioned EBS volumes independently of the account default."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import flag, items
from scanner.findings import Finding, Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "ebs_volume_encryption", "EBS volume is unencrypted",
    Pillar.SECURITY, Severity.HIGH, "AWS::EC2::Volume", Scope.REGIONAL,
    "Plan a backup and maintenance window to replace the volume with an encrypted copy.",
)
REGISTRY = {
    "service": "ec2",
    "required_actions": ("ec2:DescribeVolumes",),
    "applicability": "Provisioned EBS volumes in available or in-use state",
    "evidence_fields": ("Encrypted", "State"),
    "references": ("https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Volume.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    ec2 = ctx.client("ec2")
    for volume in items(ec2, "describe_volumes", "Volumes"):
        if volume.get("State") not in {"available", "in-use"}:
            continue
        yield flag(
            ctx, META, ctx.arn("ec2", f"volume/{volume['VolumeId']}"), volume.get("Encrypted"),
            expected=True, passing="The volume is encrypted.", failing="The volume is unencrypted.",
        )

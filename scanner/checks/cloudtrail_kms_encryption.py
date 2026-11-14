"""Check whether CloudTrail delivery uses KMS encryption."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.findings import Finding, Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "cloudtrail_kms_encryption", "CloudTrail delivery has no configured KMS key",
    Pillar.SECURITY, Severity.MEDIUM, "AWS::CloudTrail::Trail", Scope.REGIONAL,
    "Configure an approved KMS key and verify the trail and authorized log readers can use it.",
)
REGISTRY = {
    "service": "cloudtrail",
    "required_actions": ("cloudtrail:DescribeTrails",),
    "applicability": "Trails in their home Region; excludes regional shadow copies",
    "evidence_fields": ("KmsKeyId", "HomeRegion"),
    "references": (
        "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Trail.html",
        "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
    ),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    trails = ctx.client("cloudtrail").describe_trails(includeShadowTrails=False).get("trailList", [])
    for trail in trails:
        if trail.get("HomeRegion") != ctx.region:
            continue
        configured = bool(trail.get("KmsKeyId"))
        description = (
            "A KMS key is configured on the trail." if configured
            else "No KMS key is configured on the trail. This check does not assess the destination bucket encryption."
        )
        yield ctx.finding(META, Status.PASS if configured else Status.FAIL, trail["TrailARN"], description)

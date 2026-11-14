"""Check whether CloudTrail produces log integrity validation digests."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import flag
from scanner.findings import Finding, Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "cloudtrail_log_validation", "CloudTrail log integrity validation is disabled",
    Pillar.SECURITY, Severity.MEDIUM, "AWS::CloudTrail::Trail", Scope.REGIONAL,
    "Enable log file integrity validation and verify delivered digest files.",
)
REGISTRY = {
    "service": "cloudtrail",
    "required_actions": ("cloudtrail:DescribeTrails",),
    "applicability": "Trails in their home Region; excludes regional shadow copies",
    "evidence_fields": ("LogFileValidationEnabled", "HomeRegion"),
    "references": ("https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Trail.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    trails = ctx.client("cloudtrail").describe_trails(includeShadowTrails=False).get("trailList", [])
    for trail in trails:
        if trail.get("HomeRegion") != ctx.region:
            continue
        yield flag(
            ctx, META, trail["TrailARN"], trail.get("LogFileValidationEnabled"), expected=True,
            passing="The trail produces log file integrity digests.",
            failing="The trail does not produce log file integrity digests.",
        )

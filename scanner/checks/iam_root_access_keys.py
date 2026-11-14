"""Detect standing AWS access keys on the root identity."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.findings import Finding, Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "iam_root_access_keys", "Root user has an access key",
    Pillar.SECURITY, Severity.HIGH, "AWS::IAM::Root", Scope.GLOBAL,
    "Move automation to temporary role credentials, then deactivate and remove root access keys.",
)
REGISTRY = {
    "service": "iam",
    "required_actions": ("iam:GetAccountSummary",),
    "applicability": "AWS account root user",
    "evidence_fields": ("SummaryMap.AccountAccessKeysPresent",),
    "references": ("https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    summary = ctx.client("iam").get_account_summary().get("SummaryMap", {})
    present = summary.get("AccountAccessKeysPresent")
    if present == 0:
        yield ctx.finding(META, Status.PASS, ctx.account_arn, "AWS reports no root access keys.")
    elif present == 1:
        yield ctx.finding(META, Status.FAIL, ctx.account_arn, "AWS reports at least one root access key.")
    else:
        yield ctx.finding(META, Status.UNKNOWN, ctx.account_arn, "The root access key indicator is unavailable.")

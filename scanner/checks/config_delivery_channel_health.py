"""Inspect the last reported delivery state for each configured AWS Config channel."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status

V2_ONLY = True
REGISTRY = {
    "service": "config",
    "required_actions": ["config:DescribeDeliveryChannelStatus"],
    "applicability": "Existing AWS Config channels and reported snapshot, history or stream delivery states",
    "evidence_fields": ["configSnapshotDeliveryInfo.lastStatus", "configHistoryDeliveryInfo.lastStatus", "configStreamDeliveryInfo.lastStatus"],
    "references": ["https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeDeliveryChannelStatus.html"],
}
META = CheckMeta(
    "config_delivery_channel_health", "AWS Config delivery failed", Pillar.OPERATIONAL_EXCELLENCE,
    Severity.HIGH, "AWS::Config::DeliveryChannel", Scope.REGIONAL,
    "Review delivery history and permissions to the channel's S3 bucket, SNS topic and encryption key, as applicable.",
)


def run(ctx):
    response = ctx.client("config").describe_delivery_channel_status()
    for channel in response["DeliveryChannelsStatus"]:
        arn = ctx.arn("config", f"delivery-channel/{channel['name']}")
        states = {
            label: channel.get(field, {}).get("lastStatus")
            for field, label in (
                ("configSnapshotDeliveryInfo", "snapshot"),
                ("configHistoryDeliveryInfo", "history"),
                ("configStreamDeliveryInfo", "stream"),
            )
            if channel.get(field)
        }
        failed = [label for label, state in states.items() if state == "Failure"]
        if failed:
            yield ctx.finding(META, Status.FAIL, arn, f"Latest reported delivery failed for {', '.join(failed)}.")
        elif states and all(state in ("Success", "Not_Applicable", "NotApplicable") for state in states.values()) and "Success" in states.values():
            yield ctx.finding(META, Status.PASS, arn, "All applicable reported delivery types most recently succeeded.")
        else:
            yield ctx.finding(META, Status.UNKNOWN, arn, "No conclusive successful delivery status was reported.")

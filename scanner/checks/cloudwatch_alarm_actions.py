"""Detect configured metric alarm actions that are disabled."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status

META = CheckMeta(
    "cloudwatch_alarm_actions", "CloudWatch metric alarm actions disabled",
    Pillar.OPERATIONAL_EXCELLENCE, Severity.MEDIUM, "AWS::CloudWatch::Alarm", Scope.REGIONAL,
    "Check why actions were disabled. Re-enable intended actions after the maintenance or investigation ends.",
)


def run(ctx):
    cloudwatch = ctx.client("cloudwatch")
    for page in cloudwatch.get_paginator("describe_alarms").paginate(AlarmTypes=["MetricAlarm"]):
        for alarm in page["MetricAlarms"]:
            if not any(alarm.get(key) for key in ("AlarmActions", "OKActions", "InsufficientDataActions")):
                continue
            enabled = alarm.get("ActionsEnabled")
            if enabled is None:
                status, description = Status.UNKNOWN, "AWS did not return the action state."
            elif enabled:
                status, description = Status.PASS, "Configured actions are enabled."
            else:
                status, description = Status.FAIL, "Configured actions are disabled."
            yield ctx.finding(META, status, alarm["AlarmArn"], description)

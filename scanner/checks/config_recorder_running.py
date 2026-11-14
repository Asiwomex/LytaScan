"""Check the active state of existing customer-managed Config recorders."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status

V2_ONLY = True
REGISTRY = {
    "service": "config",
    "required_actions": ["config:DescribeConfigurationRecorderStatus"],
    "applicability": "Existing customer-managed AWS Config recorders",
    "evidence_fields": ["recording"],
    "references": ["https://docs.aws.amazon.com/config/latest/APIReference/API_ConfigurationRecorderStatus.html"],
}
META = CheckMeta(
    "config_recorder_running", "AWS Config recorder stopped", Pillar.OPERATIONAL_EXCELLENCE,
    Severity.MEDIUM, "AWS::Config::ConfigurationRecorder", Scope.REGIONAL,
    "Confirm recording is still intended. Review the recorder's service role and restart recording after any maintenance window.",
)


def run(ctx):
    response = ctx.client("config").describe_configuration_recorder_status()
    for recorder in response["ConfigurationRecordersStatus"]:
        if recorder.get("servicePrincipal"):
            continue
        arn = recorder.get("arn") or ctx.arn("config", f"configuration-recorder/{recorder['name']}")
        recording = recorder.get("recording")
        if recording is True:
            yield ctx.finding(META, Status.PASS, arn, "AWS reports this recorder is recording.")
        elif recording is False:
            yield ctx.finding(META, Status.FAIL, arn, "AWS reports this recorder is stopped.")
        else:
            yield ctx.finding(META, Status.UNKNOWN, arn, "AWS did not report whether this recorder is running.")

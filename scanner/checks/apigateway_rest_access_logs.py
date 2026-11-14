"""Check access log configuration on deployed REST API stages."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import rows

V2_ONLY = True
REGISTRY = {
    "service": "apigateway",
    "required_actions": ["apigateway:GET"],
    "applicability": "Deployed API Gateway REST API stages",
    "evidence_fields": ["deploymentId", "accessLogSettings.destinationArn", "accessLogSettings.format"],
    "references": ["https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html"],
}
META = CheckMeta(
    "apigateway_rest_access_logs", "REST API stage access logs not configured", Pillar.OPERATIONAL_EXCELLENCE,
    Severity.MEDIUM, "AWS::ApiGateway::Stage", Scope.REGIONAL,
    "Configure an approved access log destination and a format that omits credentials, authorization headers, and sensitive request data.",
)


def run(ctx):
    gateway = ctx.client("apigateway")
    for api in rows(gateway, "get_rest_apis", "items"):
        api_id = api["id"]
        for stage in gateway.get_stages(restApiId=api_id)["item"]:
            if not stage.get("deploymentId"):
                continue
            arn = f"arn:aws:apigateway:{ctx.region}::/restapis/{api_id}/stages/{stage['stageName']}"
            logs = stage.get("accessLogSettings", {})
            enabled = bool(logs.get("destinationArn") and logs.get("format"))
            description = "The stage has an access log destination and format." if enabled else "The stage does not have an access log destination and format."
            yield ctx.finding(META, Status.PASS if enabled else Status.FAIL, arn, description)

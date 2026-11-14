"""Check access log configuration on deployed HTTP API stages."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import rows

V2_ONLY = True
REGISTRY = {
    "service": "apigatewayv2",
    "required_actions": ["apigateway:GET"],
    "applicability": "Deployed HTTP API Gateway v2 stages",
    "evidence_fields": ["ProtocolType", "DeploymentId", "AccessLogSettings.DestinationArn", "AccessLogSettings.Format"],
    "references": ["https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html"],
}
META = CheckMeta(
    "apigateway_http_access_logs", "HTTP API stage access logs not configured", Pillar.OPERATIONAL_EXCELLENCE,
    Severity.MEDIUM, "AWS::ApiGatewayV2::Stage", Scope.REGIONAL,
    "Configure an approved access log destination and a format that omits credentials, authorization headers, and sensitive request data.",
)


def run(ctx):
    gateway = ctx.client("apigatewayv2")
    for api in rows(gateway, "get_apis", "Items"):
        if api.get("ProtocolType") != "HTTP":
            continue
        api_id = api["ApiId"]
        for stage in rows(gateway, "get_stages", "Items", ApiId=api_id):
            if not stage.get("DeploymentId"):
                continue
            arn = f"arn:aws:apigateway:{ctx.region}::/apis/{api_id}/stages/{stage['StageName']}"
            logs = stage.get("AccessLogSettings", {})
            enabled = bool(logs.get("DestinationArn") and logs.get("Format"))
            description = "The stage has an access log destination and format." if enabled else "The stage does not have an access log destination and format."
            yield ctx.finding(META, Status.PASS if enabled else Status.FAIL, arn, description)

"""Check whether DynamoDB tables are protected against accidental deletion."""

from collections.abc import Iterator

from botocore.exceptions import ClientError

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import flag
from scanner.findings import Finding, Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "dynamodb_deletion_protection", "DynamoDB table lacks deletion protection",
    Pillar.RELIABILITY, Severity.MEDIUM, "AWS::DynamoDB::Table", Scope.REGIONAL,
    "Enable deletion protection for tables that should not be removed accidentally.",
)
REGISTRY = {
    "service": "dynamodb",
    "required_actions": ("dynamodb:ListTables", "dynamodb:DescribeTable"),
    "applicability": "DynamoDB tables that are not being deleted",
    "evidence_fields": ("DeletionProtectionEnabled", "TableStatus"),
    "references": ("https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TableDescription.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    dynamodb = ctx.client("dynamodb")
    for page in dynamodb.get_paginator("list_tables").paginate():
        for name in page["TableNames"]:
            arn = ctx.arn("dynamodb", f"table/{name}")
            try:
                table = dynamodb.describe_table(TableName=name)["Table"]
            except ClientError as error:
                yield ctx.error(META, arn, error)
                continue
            if table.get("TableStatus") == "DELETING":
                continue
            yield flag(
                ctx, META, table.get("TableArn", arn), table.get("DeletionProtectionEnabled"),
                expected=True, passing="Deletion protection is enabled.", failing="Deletion protection is disabled.",
            )

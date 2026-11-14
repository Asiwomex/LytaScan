"""Check whether standalone RDS databases are protected against accidental deletion."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import flag, items
from scanner.findings import Finding, Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "rds_deletion_protection", "RDS instance lacks deletion protection",
    Pillar.RELIABILITY, Severity.MEDIUM, "AWS::RDS::DBInstance", Scope.REGIONAL,
    "Enable deletion protection on databases that should not be removed accidentally.",
)
REGISTRY = {
    "service": "rds",
    "required_actions": ("rds:DescribeDBInstances",),
    "applicability": "Standalone RDS database instances; excludes cluster members and deleting instances",
    "evidence_fields": ("DeletionProtection", "DBClusterIdentifier"),
    "references": ("https://docs.aws.amazon.com/config/latest/developerguide/rds-instance-deletion-protection-enabled.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    for database in items(ctx.client("rds"), "describe_db_instances", "DBInstances"):
        if database.get("DBClusterIdentifier") or database.get("DBInstanceStatus") == "deleting":
            continue
        yield flag(
            ctx, META, database["DBInstanceArn"], database.get("DeletionProtection"),
            expected=True, passing="Deletion protection is enabled.", failing="Deletion protection is disabled.",
        )

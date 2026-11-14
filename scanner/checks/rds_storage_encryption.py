"""Check encryption at rest on RDS database instances."""

from collections.abc import Iterator

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import flag, items
from scanner.findings import Finding, Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "rds_storage_encryption", "RDS instance storage is unencrypted",
    Pillar.SECURITY, Severity.HIGH, "AWS::RDS::DBInstance", Scope.REGIONAL,
    "Use a supported encrypted snapshot copy and restore workflow. Plan application cutover before retiring the source.",
)
REGISTRY = {
    "service": "rds",
    "required_actions": ("rds:DescribeDBInstances",),
    "applicability": "Standalone RDS database instances; cluster encryption is evaluated separately",
    "evidence_fields": ("StorageEncrypted", "DBClusterIdentifier"),
    "references": ("https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    for database in items(ctx.client("rds"), "describe_db_instances", "DBInstances"):
        if database.get("DBClusterIdentifier") or database.get("DBInstanceStatus") == "deleting":
            continue
        yield flag(
            ctx, META, database["DBInstanceArn"], database.get("StorageEncrypted"),
            expected=True, passing="Database storage is encrypted.", failing="Database storage is unencrypted.",
        )

"""Check the EFS automatic backup policy independently of custom backup plans."""

from collections.abc import Iterator

from botocore.exceptions import ClientError

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import items
from scanner.findings import Finding, Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "efs_automatic_backup", "EFS automatic backups are not enabled",
    Pillar.RELIABILITY, Severity.MEDIUM, "AWS::EFS::FileSystem", Scope.REGIONAL,
    "Verify whether a custom backup plan covers the file system. Enable EFS automatic backup if appropriate.",
)
REGISTRY = {
    "service": "efs",
    "required_actions": ("elasticfilesystem:DescribeFileSystems", "elasticfilesystem:DescribeBackupPolicy"),
    "applicability": "Available EFS file systems; this rule assesses the built-in automatic backup policy",
    "evidence_fields": ("BackupPolicy.Status", "LifeCycleState"),
    "references": ("https://docs.aws.amazon.com/efs/latest/ug/API_DescribeBackupPolicy.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    efs = ctx.client("efs")
    for filesystem in items(efs, "describe_file_systems", "FileSystems"):
        if filesystem.get("LifeCycleState") != "available":
            continue
        filesystem_id = filesystem["FileSystemId"]
        arn = filesystem.get("FileSystemArn") or ctx.arn("elasticfilesystem", f"file-system/{filesystem_id}")
        try:
            state = efs.describe_backup_policy(FileSystemId=filesystem_id).get("BackupPolicy", {}).get("Status")
        except ClientError as error:
            if error.response["Error"]["Code"] != "PolicyNotFound":
                yield ctx.error(META, arn, error)
                continue
            state = "DISABLED"
        if state == "ENABLED":
            status, description = Status.PASS, "The EFS automatic backup policy is enabled."
        elif state == "DISABLED":
            status, description = Status.FAIL, "The built-in automatic backup policy is disabled or absent."
        else:
            status, description = Status.UNKNOWN, "The automatic backup policy state is unavailable or changing."
        yield ctx.finding(META, status, arn, description)

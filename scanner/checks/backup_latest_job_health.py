"""Check the latest terminal AWS Backup job per resource within seven days."""

from datetime import timedelta

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.operations import rows

V2_ONLY = True
REGISTRY = {
    "service": "backup",
    "required_actions": ["backup:ListBackupJobs"],
    "applicability": "Resources with an observed non-aborted terminal backup job started within seven days",
    "evidence_fields": ["State", "CreationDate", "ResourceArn", "MessageCategory"],
    "references": ["https://docs.aws.amazon.com/aws-backup/latest/APIReference/API_ListBackupJobs.html"],
}
META = CheckMeta(
    "backup_latest_job_health", "Most recent AWS Backup job did not complete successfully",
    Pillar.OPERATIONAL_EXCELLENCE, Severity.HIGH, "AWS::Backup::ProtectedResource", Scope.REGIONAL,
    "Review the failed or incomplete backup job in AWS Backup. Verify that a usable recovery point is created after fixing the issue.",
)
TERMINAL = {"COMPLETED", "FAILED", "EXPIRED", "PARTIAL"}


def run(ctx):
    backup = ctx.client("backup")
    latest = {}
    for job in rows(backup, "list_backup_jobs", "BackupJobs", ByAccountId=ctx.account_id,
                    ByCreatedAfter=ctx.now - timedelta(days=7)):
        state = job.get("State")
        if state not in TERMINAL:
            continue
        resource = job.get("ResourceArn")
        when = job.get("CreationDate")
        if not resource or not when:
            yield ctx.finding(META, Status.UNKNOWN, ctx.account_arn, "A recent terminal backup job did not identify its resource or start time.")
            continue
        current = latest.get(resource)
        if current is None or when > current["CreationDate"]:
            latest[resource] = job
    for arn, job in latest.items():
        state = job["State"]
        if state != "COMPLETED":
            yield ctx.finding(META, Status.FAIL, arn, f"The latest terminal backup job was {state.lower()} during the seven-day lookback.")
        elif job.get("MessageCategory") == "SUCCESS":
            yield ctx.finding(META, Status.PASS, arn, "The latest backup job completed successfully during the seven-day lookback.")
        elif job.get("MessageCategory"):
            yield ctx.finding(META, Status.FAIL, arn, "The latest backup job completed with issues during the seven-day lookback.")
        else:
            yield ctx.finding(META, Status.UNKNOWN, arn, "The latest backup job completed but AWS did not report its success category.")

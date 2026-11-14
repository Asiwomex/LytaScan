"""Versioned metadata for the original checks and opt-in v2 checks."""

from scanner.engine import discover_checks

REGISTRY_VERSION = "2.1.0"
LEGACY_ACTIONS = {
    "autoscaling_single_az": ("autoscaling:DescribeAutoScalingGroups",),
    "cloudtrail_multi_region": ("cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"),
    "dynamodb_pitr": ("dynamodb:ListTables", "dynamodb:DescribeContinuousBackups"),
    "ebs_default_encryption": ("ec2:GetEbsEncryptionByDefault",),
    "ebs_gp2_volume": ("ec2:DescribeVolumes",),
    "ebs_old_snapshot": ("ec2:DescribeSnapshots",),
    "ebs_unattached_volume": ("ec2:DescribeVolumes",),
    "ec2_security_group_open_admin_ports": ("ec2:DescribeSecurityGroups",),
    "ec2_unassociated_eip": ("ec2:DescribeAddresses",),
    "elb_no_targets": ("elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTargetGroups",
                       "elasticloadbalancing:DescribeTargetHealth"),
    "guardduty_enabled": ("guardduty:ListDetectors", "guardduty:GetDetector"),
    "iam_access_key_age": ("iam:ListUsers", "iam:ListAccessKeys"),
    "iam_policy_full_admin": ("iam:ListPolicies", "iam:GetPolicyVersion"),
    "iam_root_mfa": ("iam:GetAccountSummary",),
    "iam_user_mfa": ("iam:ListUsers", "iam:GetLoginProfile", "iam:ListMFADevices"),
    "lambda_dead_letter_queue": ("lambda:ListFunctions", "lambda:ListFunctionEventInvokeConfigs",
                                "lambda:ListEventSourceMappings", "lambda:GetPolicy"),
    "logs_no_retention": ("logs:DescribeLogGroups",),
    "rds_backup_retention": ("rds:DescribeDBInstances",),
    "rds_multi_az": ("rds:DescribeDBInstances",),
    "rds_public_access": ("rds:DescribeDBInstances",),
    "s3_public_access_block": ("s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetAccountPublicAccessBlock",
                               "s3:GetBucketPublicAccessBlock"),
    "s3_versioning": ("s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketVersioning"),
}
V2_CHECKS = {
    "cloudwatch_alarm_actions": (
        "cloudwatch", ("cloudwatch:DescribeAlarms",), "Metric alarms with configured actions",
        ("ActionsEnabled",), "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarms.html",
    ),
    "ec2_ebs_optimization": (
        "ec2", ("ec2:DescribeInstances", "ec2:DescribeInstanceTypes"), "Running EBS-backed instances with optional optimization",
        ("EbsOptimizedSupport", "EbsOptimized"), "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html",
    ),
    "s3_incomplete_multipart_cleanup": (
        "s3", ("s3:ListAllMyBuckets", "s3:GetLifecycleConfiguration"), "General purpose S3 buckets",
        ("Status", "Filter", "AbortIncompleteMultipartUpload"), "https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpu-abort-incomplete-mpu-lifecycle-config.html",
    ),
}


def catalog():
    for check in discover_checks(include_v2=True):
        meta = check.meta
        details = V2_CHECKS.get(meta.check_id)
        actions = details[1] if details else LEGACY_ACTIONS.get(meta.check_id, ())
        metadata = check.registry or {
            "service": details[0] if details else actions[0].split(":")[0],
            "required_actions": list(actions),
            "applicability": details[2] if details else None,
            "evidence_fields": list(details[3]) if details else [],
            "references": [details[4]] if details else [],
        }
        yield {
            "check_id": meta.check_id, "version": "1.0.0", "primary_pillar": meta.pillar.value,
            "title": meta.title, "scope": meta.scope.value, "severity": meta.severity.value,
            "resource_type": meta.resource_type, "remediation": meta.remediation,
            **metadata,
        }


def markdown_catalog() -> str:
    checks = list(catalog())
    lines = [
        "# Scanner check catalog", "",
        f"Registry {REGISTRY_VERSION} contains {len(checks)} rules. Generate this page with",
        "`python -m scanner --catalog --catalog-format markdown`.", "",
        "| Check | Pillar | Severity | Scope | Read permissions |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in checks:
        references = check["references"]
        title = check["title"].replace("|", "\\|")
        rule = f"`{check['check_id']}`<br>{title}"
        if references:
            rule += f" ([AWS documentation]({references[0]}))"
        pillar = check["primary_pillar"].replace("_", " ").title()
        actions = "<br>".join(f"`{action}`" for action in check["required_actions"])
        lines.append(f"| {rule} | {pillar} | {check['severity']} | {check['scope']} | {actions} |")
    return "\n".join(lines)

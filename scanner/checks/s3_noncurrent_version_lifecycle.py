"""Identify versioned buckets with no bucket-wide noncurrent lifecycle policy."""

from botocore.exceptions import ClientError

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.s3 import bucket_arn, bucket_names

V2_ONLY = True
META = CheckMeta(
    "s3_noncurrent_version_lifecycle", "Versioned S3 bucket lacks bucket-wide noncurrent lifecycle management",
    Pillar.SUSTAINABILITY, Severity.LOW, "AWS::S3::Bucket", Scope.GLOBAL,
    "Review storage tiers and retention requirements for noncurrent versions. Consider a transition or retention policy suited to the bucket.",
)
REGISTRY = {
    "service": "s3",
    "required_actions": ("s3:ListAllMyBuckets", "s3:GetBucketVersioning", "s3:GetLifecycleConfiguration"),
    "applicability": "General purpose buckets with versioning enabled or suspended",
    "evidence_fields": ("Status", "Filter", "NoncurrentVersionExpiration", "NoncurrentVersionTransitions"),
    "references": ("https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html",),
    "advisory": True,
}


def manages_noncurrent_versions(rule):
    if rule["Status"] != "Enabled" or rule.get("Prefix") or rule.get("Filter", {}) not in ({}, {"Prefix": ""}):
        return False
    expiration = rule.get("NoncurrentVersionExpiration", {}).get("NoncurrentDays", 0)
    return expiration > 0 or any(
        transition.get("NoncurrentDays", 0) > 0 and transition.get("StorageClass")
        for transition in rule.get("NoncurrentVersionTransitions", [])
    )


def run(ctx):
    s3 = ctx.client("s3")
    for bucket in bucket_names(s3):
        arn = bucket_arn(bucket)
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status")
            if versioning not in ("Enabled", "Suspended"):
                continue
            try:
                rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
            except ClientError as error:
                if error.response["Error"]["Code"] != "NoSuchLifecycleConfiguration":
                    raise
                rules = []
        except ClientError as error:
            yield ctx.error(META, arn, error)
            continue
        managed = any(manages_noncurrent_versions(rule) for rule in rules)
        description = (
            "An enabled bucket-wide rule manages noncurrent versions." if managed else
            "No enabled bucket-wide transition or expiration policy manages noncurrent versions. "
            "This is a storage efficiency recommendation."
        )
        yield ctx.finding(META, Status.PASS if managed else Status.FAIL, arn, description)

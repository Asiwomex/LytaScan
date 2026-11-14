"""Assess lifecycle protection against retained incomplete multipart data."""

from botocore.exceptions import ClientError

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status
from scanner.s3 import bucket_arn, bucket_names

META = CheckMeta(
    "s3_incomplete_multipart_cleanup", "S3 bucket lacks bucket-wide multipart upload cleanup",
    Pillar.SUSTAINABILITY, Severity.LOW, "AWS::S3::Bucket", Scope.GLOBAL,
    "Review valid upload durations and add a bucket-wide lifecycle rule to abort abandoned multipart uploads.",
)


def run(ctx):
    s3 = ctx.client("s3")
    for bucket in bucket_names(s3):
        arn = bucket_arn(bucket)
        try:
            rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
        except ClientError as error:
            if error.response["Error"]["Code"] != "NoSuchLifecycleConfiguration":
                yield ctx.error(META, arn, error)
                continue
            rules = []
        protected = any(
            rule["Status"] == "Enabled" and rule.get("AbortIncompleteMultipartUpload", {}).get("DaysAfterInitiation", 0) > 0
            and not rule.get("Prefix") and rule.get("Filter", {}) in ({}, {"Prefix": ""})
            for rule in rules
        )
        description = (
            "A bucket-wide abort rule is enabled." if protected else
            "There is no enabled bucket-wide abort rule. This is a storage efficiency recommendation."
        )
        yield ctx.finding(META, Status.PASS if protected else Status.FAIL, arn, description)

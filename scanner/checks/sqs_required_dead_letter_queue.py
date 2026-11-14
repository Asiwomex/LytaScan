"""Check redrive policies for queues explicitly marked as requiring a DLQ."""

from collections.abc import Iterator
import json
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from scanner.check import CheckContext, CheckMeta, Scope
from scanner.config_inventory import items
from scanner.findings import Finding, Pillar, Severity, Status

REQUIRE_DLQ_TAG = "PillarscanRequireDlq"
V2_ONLY = True
META = CheckMeta(
    "sqs_required_dead_letter_queue", "SQS queue marked for dead-letter handling has no redrive policy",
    Pillar.RELIABILITY, Severity.MEDIUM, "AWS::SQS::Queue", Scope.REGIONAL,
    "Configure a compatible dead-letter queue and set the maximum receives to suit the consumer's retry policy.",
)
REGISTRY = {
    "service": "sqs",
    "required_actions": ("sqs:ListQueues", "sqs:ListQueueTags", "sqs:GetQueueAttributes"),
    "applicability": f"Queues tagged {REQUIRE_DLQ_TAG}=true; other queues may use a different failure-handling design",
    "evidence_fields": (f"Tags.{REQUIRE_DLQ_TAG}", "RedrivePolicy.deadLetterTargetArn", "RedrivePolicy.maxReceiveCount"),
    "references": ("https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html",),
}


def run(ctx: CheckContext) -> Iterator[Finding]:
    sqs = ctx.client("sqs")
    for url in items(sqs, "list_queues", "QueueUrls"):
        name = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
        arn = ctx.arn("sqs", name)
        try:
            tags = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
            if tags.get(REQUIRE_DLQ_TAG, "").strip().lower() != "true":
                continue
            policy = sqs.get_queue_attributes(
                QueueUrl=url, AttributeNames=["RedrivePolicy"],
            ).get("Attributes", {}).get("RedrivePolicy")
        except ClientError as error:
            yield ctx.error(META, arn, error)
            continue
        if not policy:
            yield ctx.finding(META, Status.FAIL, arn, "The queue is marked as requiring a DLQ and has no redrive policy.")
            continue
        try:
            redrive = json.loads(policy)
            if not redrive["deadLetterTargetArn"].startswith("arn:") or int(redrive["maxReceiveCount"]) <= 0:
                raise ValueError("unrecognized redrive policy")
        except (ValueError, KeyError, TypeError, AttributeError):
            yield ctx.finding(META, Status.UNKNOWN, arn, "AWS did not return a recognized redrive policy.")
            continue
        yield ctx.finding(META, Status.PASS, arn, "A redrive policy names a dead-letter queue and specifies a receive limit.")

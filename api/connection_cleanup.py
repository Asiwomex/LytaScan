"""Send generation-scoped cleanup to the scanner queue."""

import json
import os

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from scanner.org_jobs import OrgJobs


def clean_now(store, org_id, generation):
    OrgJobs(store.table).purge_connection(org_id, generation)
    return True


def get_cleanup_dispatcher():
    return dispatch_cleanup


def dispatch_cleanup(store, org_id, generation):
    queue_url = os.environ.get("SCAN_QUEUE_URL")
    if not queue_url:
        return False
    try:
        boto3.client("sqs", config=Config(connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 2})).send_message(
            QueueUrl=queue_url, MessageBody=json.dumps({
                "operation": "org_cleanup", "organization_id": org_id, "generation": generation,
            }),
        )
    except (BotoCoreError, ClientError):
        return False
    return True

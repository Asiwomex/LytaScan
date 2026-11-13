"""Organization scan queue records, leases and result publication."""

import time
from datetime import datetime, timezone
from uuid import uuid4

from botocore.exceptions import ClientError

from scanner.organizations import OrganizationStore, connection_key, member_check, org_key
from scanner.store import ScanStore

SCAN_ROLES = ("owner", "administrator", "engineer")
READ_ROLES = (*SCAN_ROLES, "security_analyst", "viewer")
ACTIVE = ("queued", "running")
WINDOW = 45 * 60
LEASE = 135


class JobConflict(Exception):
    pass


class OrgJobs(OrganizationStore):
    def job(self, org, job_id):
        return self._get(org_key(org, f"JOB#{job_id}"))

    def jobs(self, org):
        return self._list(f"ORG#{org}", "JOB#")

    def _put(self, item, condition, values=None):
        args = {"TableName": self.table.name, "Item": item, "ConditionExpression": condition}
        if values:
            args["ExpressionAttributeValues"] = values
        return {"Put": args}

    def _update(self, key, expression, condition, values):
        update = {
            "TableName": self.table.name, "Key": key,
            "UpdateExpression": expression,
            "ConditionExpression": condition,
            "ExpressionAttributeValues": values,
        }
        if "#state" in expression or "#state" in condition:
            update["ExpressionAttributeNames"] = {"#state": "state"}
        return {"Update": update}

    def transact(self, *actions):
        try:
            self._transact(*actions)
        except ClientError as error:
            if error.response["Error"]["Code"] != "TransactionCanceledException":
                raise
            raise JobConflict from None

    def connection_check(self, org, account, generation, required_status="verified"):
        return {"ConditionCheck": {
            "TableName": self.table.name, "Key": connection_key(org, account),
            "ConditionExpression": "account_connection_id = :id AND #state = :state",
            "ExpressionAttributeNames": {"#state": "status"},
            "ExpressionAttributeValues": {":id": generation, ":state": required_status},
        }}

    def enqueue(self, org, actor, connection, request_id):
        job_id = request_id
        account = connection["aws_account_id"]
        generation = connection["account_connection_id"]
        now = int(time.time())
        job_key = org_key(org, f"JOB#{job_id}")
        deadline = now + WINDOW
        day = datetime.now(timezone.utc).date().isoformat()
        for slot in range(2):
            job = {
                **job_key, "job_id": job_id, "organization_id": org, "aws_account_id": account,
                "account_connection_id": generation, "actor": actor, "state": "queued",
                "region": connection["region"], "created_at": now, "deadline": deadline,
                "slot": slot, "expires_at": now + 90 * 86400, "schema_version": 1,
            }
            try:
                self.transact(
                    member_check(self.table, actor, org, SCAN_ROLES, generation),
                    self.connection_check(org, account, generation),
                    self._put(job, "attribute_not_exists(PK)"),
                    *(self._put(
                        {**key, "job_id": job_id, "expires_at": deadline},
                        "attribute_not_exists(PK) OR expires_at <= :now", {":now": now},
                    ) for key in self._locks(job)),
                    self._update(
                        org_key(org, f"SCAN_QUOTA#{account}#{day}"), "SET expires_at = :expiry ADD requests :one",
                        "attribute_not_exists(requests) OR requests < :limit",
                        {":expiry": now + 2 * 86400, ":one": 1, ":limit": 3},
                    ),
                )
                return job
            except JobConflict:
                previous = self.job(org, job_id)
                if previous:
                    if (previous["actor"], previous["account_connection_id"]) != (actor, generation):
                        raise
                    return previous
        raise JobConflict

    @staticmethod
    def _locks(job):
        org = job["organization_id"]
        return (
            org_key(org, f"SCAN_LOCK#{job['aws_account_id']}"),
            org_key(org, f"SCAN_SLOT#{job['slot']}"),
        )

    def release(self, job):
        for key in self._locks(job):
            try:
                self.table.delete_item(
                    Key=key, ConditionExpression="job_id = :id",
                    ExpressionAttributeValues={":id": job["job_id"]},
                )
            except ClientError as error:
                if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                    raise

    def cancel(self, job, actor):
        org = job["organization_id"]
        roles = SCAN_ROLES if job["actor"] == actor else ("owner", "administrator")
        self.transact(
            member_check(self.table, actor, org, roles, job["account_connection_id"]),
            self._update(
                org_key(org, f"JOB#{job['job_id']}"), "SET finished_at = :value, #state = :cancelled",
                "#state IN (:queued, :running)",
                {":value": int(time.time()), ":cancelled": "cancelled", ":queued": "queued", ":running": "running"},
            ),
        )
        if job["state"] == "queued":
            # If the worker claimed it concurrently, leave the lock in place.
            current = self.job(org, job["job_id"])
            if current and "attempt" not in current:
                self.release(job)

    def claim(self, job):
        now = int(time.time())
        attempt = uuid4().hex
        org = job["organization_id"]
        self.transact(
            member_check(self.table, job["actor"], org, SCAN_ROLES, job["account_connection_id"]),
            self.connection_check(org, job["aws_account_id"], job["account_connection_id"]),
            self._update(
                org_key(org, f"JOB#{job['job_id']}"),
                "SET #state = :running, attempt = :attempt, lease_until = :lease, started_at = if_not_exists(started_at, :now)",
                "deadline > :lease AND (#state = :queued OR (#state = :running AND lease_until <= :now))",
                {":running": "running", ":queued": "queued", ":attempt": attempt, ":lease": now + LEASE, ":now": now},
            ),
        )
        return attempt

    def finish(self, job, attempt, state, **fields):
        org = job["organization_id"]
        fields.update(state=state, finished_at=int(time.time()))
        values = {f":v{i}": value for i, value in enumerate(fields.values())}
        checks = ()
        if state in ("complete", "partial"):
            checks = (
                member_check(self.table, job["actor"], org, SCAN_ROLES, job["account_connection_id"]),
                self.connection_check(org, job["aws_account_id"], job["account_connection_id"]),
            )
        self.transact(*checks, self._update(
            org_key(org, f"JOB#{job['job_id']}"),
            "SET " + ", ".join(f"{'#state' if field == 'state' else field} = {value}" for field, value in zip(fields, values)),
            "#state = :running AND attempt = :attempt AND lease_until > :now",
            {**values, ":running": "running", ":attempt": attempt, ":now": int(time.time())},
        ))
        self.release(job)


def run_job(store: OrgJobs, org: str, job_id: str, scan):
    job = store.job(org, job_id)
    if not job:
        return
    if job["state"] not in ACTIVE:
        if job["state"] != "cancelled" or job.get("lease_until", 0) <= time.time():
            store.release(job)
        return
    if job["deadline"] <= time.time() + LEASE:
        return
    try:
        attempt = store.claim(job)
    except JobConflict:
        current = store.job(org, job_id)
        now = int(time.time())
        if current and current["state"] == "running" and current["lease_until"] > now:
            # Do not acknowledge a redelivery while another attempt owns the lease.
            # A failed attempt must still be eligible for the queue's retry.
            raise
        if not current or current["state"] not in ACTIVE:
            return
        # A revoked member, replaced connection or duplicate message cannot scan.
        member = store.membership(job["actor"], org)
        if not member or member["role"] not in SCAN_ROLES or (
            member["role"] == "engineer" and member.get("allowed_account") != job["account_connection_id"]
        ) or not (
            (connection := store.connection(org, job["aws_account_id"]))
            and connection["status"] == "verified"
            and connection["account_connection_id"] == job["account_connection_id"]
        ):
            try:
                store._transact(store._update(
                    org_key(org, f"JOB#{job_id}"), "SET #state = :failed, error_message = :message",
                    "#state = :queued OR (#state = :running AND lease_until <= :now)",
                    {":failed": "failed", ":queued": "queued", ":running": "running", ":now": int(time.time()),
                     ":message": "The connection or scan permission changed."},
                ))
                store.release(job)
            except ClientError as error:
                if error.response["Error"]["Code"] != "TransactionCanceledException":
                    raise
        elif current["deadline"] > now + LEASE:
            raise
        return
    connection = store.connection(org, job["aws_account_id"])
    if not connection or connection["status"] != "verified" or connection["account_connection_id"] != job["account_connection_id"]:
        _fail_job(store, job, attempt, "The connection changed before the scan started.")
        return
    try:
        report = scan(connection, job["region"])
        if report["scan"]["account_id"] != job["aws_account_id"]:
            raise ValueError("The AWS account identity changed.")
        result_owner = f"ORG#{org}#{job['account_connection_id']}#{job_id}#{attempt}"
        scan_id = ScanStore(store.table).put_scan(report, owner=result_owner)
        counts = {status: sum(f["status"] == status for f in report["findings"]) for status in ("pass", "fail", "error")}
    except (ClientError, ValueError) as error:
        if isinstance(error, ClientError) and error.response["Error"]["Code"] not in ("AccessDenied", "UnauthorizedOperation", "AccessDeniedException"):
            raise
        _fail_job(store, job, attempt, "Unable to scan the verified AWS account.")
        return
    try:
        store.finish(job, attempt, "partial" if counts["error"] else "complete",
                     result_owner=result_owner, scan_id=scan_id, counts=counts)
    except JobConflict:
        # The report is unreferenced and expires; the job never exposes it.
        _fail_job(store, job, attempt, "The connection or scan permission changed.")


def _fail_job(store, job, attempt, message):
    try:
        store.finish(job, attempt, "failed", error_message=message)
    except JobConflict:
        current = store.job(job["organization_id"], job["job_id"])
        if current and current["state"] == "cancelled" and current.get("attempt") == attempt:
            store.release(job)

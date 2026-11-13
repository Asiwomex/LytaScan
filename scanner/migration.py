"""Copy explicitly owned legacy scan history into a verified organization account."""

import time
from datetime import datetime
from hashlib import sha256
from uuid import uuid4

from scanner.accounts import tenant_key
from scanner.organizations import member_check, org_key
from scanner.org_jobs import OrgJobs
from scanner.store import ScanStore, summarise


class MigrationUnavailable(Exception):
    pass


class LegacyMigration(OrgJobs):
    def source(self, actor, account_id):
        # Only the requester's live legacy connection establishes provenance.
        legacy = self._get({"PK": f"USER#{actor}", "SK": f"ACCOUNT#{account_id}"})
        if not legacy or legacy.get("aws_account_id") != account_id or account_id == "000000000000":
            raise MigrationUnavailable
        owner = tenant_key(actor, account_id)
        items = self._list(f"ACCOUNT#{owner}", "SCAN#")
        return [
            item for item in items
            if item.get("account_id") == account_id and item.get("expires_at", 0) > time.time()
        ]

    @staticmethod
    def checkpoint(org, connection, actor, scan_id):
        generation = connection["account_connection_id"]
        job_id = sha256(f"legacy:{generation}:{actor}:{scan_id}".encode()).hexdigest()[:32]
        return org_key(org, f"JOB#{job_id}"), job_id

    def transfer(self, org, connection, actor, scan_id):
        account_id = connection["aws_account_id"]
        source = next((item for item in self.source(actor, account_id) if item["scan_id"] == scan_id), None)
        if source is None:
            raise MigrationUnavailable
        key, job_id = self.checkpoint(org, connection, actor, scan_id)
        current = self._get(key)
        if current and current["state"] != "rolled_back":
            return current
        scans = ScanStore(self.table)
        legacy_owner = tenant_key(actor, account_id)
        report = scans.get_scan(legacy_owner, scan_id, consistent=True)
        if not report or any(f.get("account_id") != account_id for f in report["findings"]):
            raise MigrationUnavailable
        summary = summarise(report)
        if any(summary[field] != source[field] for field in ("passed", "failed", "errored", "scan_id")):
            raise MigrationUnavailable
        expiry = int(source["expires_at"])
        if expiry <= time.time():
            raise MigrationUnavailable
        generation = connection["account_connection_id"]
        owner = f"ORG#{org}#{generation}#LEGACY#{job_id}#{uuid4().hex}"
        scans.put_scan(report, owner=owner, expires_at=expiry)
        job = {
            **key, "job_id": job_id, "organization_id": org, "aws_account_id": account_id,
            "account_connection_id": generation, "actor": actor, "schema_version": 1,
            "region": ", ".join(summary["regions"]) or "global",
            "state": "partial" if summary["errored"] else "complete",
            "created_at": int(datetime.fromisoformat(summary["started_at"]).timestamp()),
            "finished_at": int(datetime.fromisoformat(summary["finished_at"]).timestamp()),
            "expires_at": expiry, "scan_id": scan_id, "result_owner": owner, "source": "legacy",
            "counts": {"pass": summary["passed"], "fail": summary["failed"], "error": summary["errored"]},
        }
        put = self._put(job, "attribute_not_exists(PK) OR #state = :rolled", {":rolled": "rolled_back"})
        put["Put"]["ExpressionAttributeNames"] = {"#state": "state"}
        self.transact(
            member_check(self.table, actor, org, ("owner",)),
            self.connection_check(org, account_id, generation),
            {"ConditionCheck": {
                "TableName": self.table.name, "Key": {"PK": f"USER#{actor}", "SK": f"ACCOUNT#{account_id}"},
                "ConditionExpression": "aws_account_id = :account", "ExpressionAttributeValues": {":account": account_id},
            }},
            {"ConditionCheck": {
                "TableName": self.table.name, "Key": {"PK": f"ACCOUNT#{legacy_owner}", "SK": f"SCAN#{scan_id}"},
                "ConditionExpression": "expires_at > :now AND account_id = :account",
                "ExpressionAttributeValues": {":now": int(time.time()), ":account": account_id},
            }},
            put,
        )
        return job

    def rollback(self, org, actor, job):
        update = self._update(
            org_key(org, f"JOB#{job['job_id']}"), "SET #state = :rolled REMOVE result_owner",
            "#state IN (:complete, :partial) AND #source = :legacy",
            {":rolled": "rolled_back", ":complete": "complete", ":partial": "partial", ":legacy": "legacy"},
        )
        update["Update"]["ExpressionAttributeNames"]["#source"] = "source"
        self.transact(member_check(self.table, actor, org, ("owner",)), update)

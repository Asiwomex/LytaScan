"""Assess optional EBS optimization on running, EBS-backed instances."""

from scanner.check import CheckMeta, Scope
from scanner.findings import Pillar, Severity, Status

META = CheckMeta(
    "ec2_ebs_optimization", "Optional EBS optimization disabled",
    Pillar.PERFORMANCE_EFFICIENCY, Severity.LOW, "AWS::EC2::Instance", Scope.REGIONAL,
    "Review workload I/O and instance costs. Enable optional EBS optimization when dedicated bandwidth is warranted.",
)


def run(ctx):
    ec2 = ctx.client("ec2")
    support_by_type = {}
    for page in ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]},
                 {"Name": "root-device-type", "Values": ["ebs"]}],
    ):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                instance_type = instance["InstanceType"]
                if instance_type not in support_by_type:
                    types = ec2.describe_instance_types(InstanceTypes=[instance_type])["InstanceTypes"]
                    support_by_type[instance_type] = (
                        types[0].get("EbsInfo", {}).get("EbsOptimizedSupport") if types else None
                    )
                support = support_by_type[instance_type]
                arn = ctx.arn("ec2", f"instance/{instance['InstanceId']}")
                if support in ("default", "unsupported"):
                    continue
                enabled = instance.get("EbsOptimized")
                if support != "supported" or enabled is None:
                    status, description = Status.UNKNOWN, "EBS optimization capability or configuration is unavailable."
                elif enabled:
                    status, description = Status.PASS, "Optional dedicated EBS bandwidth is enabled."
                else:
                    status, description = Status.FAIL, "Optional dedicated EBS bandwidth is disabled. Review actual workload demand."
                yield ctx.finding(META, status, arn, description)

"""Identify paid gp3 throughput configurations for review using observed I/O."""

from scanner.check import CheckMeta, Scope
from scanner.efficiency_metrics import PERIOD, Metric, Target, measure, metric_registry, percentile, setting
from scanner.findings import Pillar, Severity, Status

V2_ONLY = True
BASELINE_MIB = 125
META = CheckMeta(
    "ebs_gp3_throughput_review", "Paid gp3 throughput has low observed hourly utilization",
    Pillar.COST, Severity.LOW, "AWS::EC2::Volume", Scope.REGIONAL,
    "Review burst demand, peak throughput and latency at finer resolution before changing provisioned throughput.",
)
REGISTRY = metric_registry(
    "ebs", ("ec2:DescribeVolumes",), "Attached gp3 volumes configured for throughput above 125 MiB/s",
    ("Throughput", "VolumeReadBytes", "VolumeWriteBytes"),
    "https://docs.aws.amazon.com/ebs/latest/userguide/using_cloudwatch_ebs.html",
    thresholds={"EBS_GP3_REVIEW_MIB_PER_SECOND": 100}, advisory=True,
)
METRICS = (Metric("VolumeReadBytes", "Sum", "Bytes"), Metric("VolumeWriteBytes", "Sum", "Bytes"))


def run(ctx):
    threshold = setting("EBS_GP3_REVIEW_MIB_PER_SECOND", 100, 1, BASELINE_MIB)
    ec2 = ctx.client("ec2")
    targets = []
    for page in ec2.get_paginator("describe_volumes").paginate(Filters=[
        {"Name": "volume-type", "Values": ["gp3"]},
        {"Name": "status", "Values": ["in-use"]},
    ]):
        for volume in page["Volumes"]:
            volume_id = volume["VolumeId"]
            arn = ctx.arn("ec2", f"volume/{volume_id}")
            provisioned = volume.get("Throughput")
            if provisioned is None:
                yield ctx.finding(META, Status.UNKNOWN, arn, "Provisioned throughput was unavailable.")
            elif provisioned > BASELINE_MIB:
                targets.append(Target(arn, (("VolumeId", volume_id),), provisioned))

    def evaluate(target, samples):
        hourly_rates = [(read + write) / PERIOD / (1024 ** 2) for read, write in zip(*samples, strict=True)]
        value = percentile(hourly_rates, 0.95)
        return value >= threshold, (
            f"95th percentile hourly throughput averaged {value:.1f} MiB/s against "
            f"{target.limit:g} MiB/s currently provisioned and a {threshold} MiB/s review threshold. "
            "Hourly averages can conceal short bursts."
        )

    yield from measure(ctx, META, targets, "AWS/EBS", METRICS, evaluate)

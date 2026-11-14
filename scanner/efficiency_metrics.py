"""Bounded CloudWatch sampling shared by efficiency checks."""

from __future__ import annotations

import math
import os
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from itertools import batched

from botocore.exceptions import ClientError

from scanner.check import CheckContext, CheckMeta
from scanner.findings import Finding, Status, format_timestamp

METRIC_ACTION = "cloudwatch:GetMetricData"
METRIC_API = "https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html"
PERIOD = 3600
QUERY_BATCH = 25


@dataclass(frozen=True)
class Metric:
    name: str
    statistic: str
    unit: str


@dataclass(frozen=True)
class Target:
    arn: str
    dimensions: tuple[tuple[str, str], ...]
    limit: float | None = None


@dataclass
class Series:
    samples: dict[datetime, float]
    bad_response: bool = False
    awaiting_page: bool = False

    def usable(self, expected: int, minimum: float) -> bool:
        return not (self.bad_response or self.awaiting_page) and len(self.samples) >= math.ceil(expected * minimum)


def setting(name: str, default: int, minimum: int, maximum: int) -> int:
    value = int(os.getenv(f"PILLARSCAN_{name}", default))
    if not minimum <= value <= maximum:
        raise ValueError(f"PILLARSCAN_{name} must be between {minimum} and {maximum}")
    return value


def percentile(values: Iterable[float], rank: float) -> float:
    data = sorted(values)
    return data[max(0, math.ceil(rank * len(data)) - 1)]


def _collect(client, namespace, batch, metrics, start, end):
    queries = []
    targets = {}
    for target in batch:
        for metric in metrics:
            key = f"m{len(queries)}"
            targets[key] = Series({})
            queries.append({
                "Id": key,
                "MetricStat": {
                    "Metric": {
                        "Namespace": namespace,
                        "MetricName": metric.name,
                        "Dimensions": [{"Name": name, "Value": value} for name, value in target.dimensions],
                    },
                    "Period": PERIOD, "Stat": metric.statistic,
                },
                "ReturnData": True,
            })
    pages = client.get_paginator("get_metric_data").paginate(
        MetricDataQueries=queries, StartTime=start, EndTime=end, ScanBy="TimestampAscending",
    )
    for page in pages:
        for result in page["MetricDataResults"]:
            series = targets.get(result["Id"])
            if series is None:
                continue
            timestamps, values = result.get("Timestamps", []), result.get("Values", [])
            status = result.get("StatusCode")
            partial_page = status == "PartialData" and bool(page.get("NextToken"))
            if (status != "Complete" and not partial_page) or len(timestamps) != len(values):
                series.bad_response = True
                continue
            series.awaiting_page = partial_page
            for timestamp, value in zip(timestamps, values, strict=True):
                if (
                    start <= timestamp < end
                    and (timestamp - start).total_seconds() % PERIOD == 0
                    and math.isfinite(value)
                    and value >= 0
                ):
                    series.samples[timestamp] = value
    return list(targets.values())


def measure(
    ctx: CheckContext,
    meta: CheckMeta,
    targets: Iterable[Target],
    namespace: str,
    metrics: tuple[Metric, ...],
    evaluate: Callable[[Target, tuple[list[float], ...]], tuple[bool | None, str]],
    *,
    minimum_coverage: float = 0.8,
) -> Iterator[Finding]:
    """Evaluate a bounded list of resources, preserving unknowns and actual sample counts."""
    days = setting("METRIC_LOOKBACK_DAYS", 14, 14, 30)
    max_targets = setting("METRIC_TARGET_LIMIT", 50, 1, 200)
    # Exclude the most recent incomplete hour and allow an hour for metric delivery.
    end = ctx.now.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    start = end - timedelta(days=days)
    expected = days * 24
    window = f"{format_timestamp(start)} to {format_timestamp(end)}, hourly buckets"
    limited = []
    for target in targets:
        if len(limited) == max_targets:
            yield ctx.finding(meta, Status.SKIPPED, ctx.account_arn,
                              f"Metric target limit reached ({max_targets}). Additional resources were not evaluated.",
                              reason_code="metric_target_limit")
            break
        limited.append(target)
    if not limited:
        return

    client = ctx.client("cloudwatch")
    for batch in batched(limited, QUERY_BATCH // len(metrics)):
        try:
            data = _collect(client, namespace, batch, metrics, start, end)
        except ClientError as exc:
            for target in batch:
                yield ctx.error(meta, target.arn, exc)
            continue
        for index, target in enumerate(batch):
            samples = data[index * len(metrics):(index + 1) * len(metrics)]
            quality = ", ".join(
                f"{metric.name} {metric.statistic}: {len(series.samples)}/{expected} samples"
                for metric, series in zip(metrics, samples, strict=True)
            )
            common = set.intersection(*(set(series.samples) for series in samples))
            if not all(series.usable(expected, minimum_coverage) for series in samples) or len(common) < math.ceil(expected * minimum_coverage):
                yield ctx.finding(
                    meta, Status.UNKNOWN, target.arn,
                    f"Insufficient metrics. Requires {minimum_coverage:.0%} complete overlapping hourly coverage. {quality}. Window {window}.",
                    reason_code="insufficient_metrics",
                )
                continue
            timestamps = sorted(common)
            passed, detail = evaluate(target, tuple([series.samples[stamp] for stamp in timestamps] for series in samples))
            status = Status.UNKNOWN if passed is None else Status.PASS if passed else Status.FAIL
            yield ctx.finding(meta, status, target.arn, f"{detail} {quality}. Window {window}.",
                              reason_code="insufficient_metrics" if status == Status.UNKNOWN else None)


def metric_registry(service, actions, applicability, metrics, reference, **extra):
    return {
        "service": service,
        "required_actions": (*actions, METRIC_ACTION),
        "applicability": applicability,
        "evidence_fields": (*metrics, "window", "sample_counts", "threshold"),
        "references": (reference, METRIC_API),
        **extra,
    }

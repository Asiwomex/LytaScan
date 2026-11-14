"""Assess Lambda duration against a common current timeout."""

from scanner.check import CheckMeta, Scope
from scanner.efficiency_metrics import Metric, measure, metric_registry, percentile, setting
from scanner.efficiency_resources import lambda_timeout_targets
from scanner.findings import Pillar, Severity, Status

V2_ONLY = True
META = CheckMeta(
    "lambda_duration_headroom", "Lambda has low observed timeout headroom",
    Pillar.PERFORMANCE_EFFICIENCY, Severity.MEDIUM, "AWS::Lambda::Function", Scope.REGIONAL,
    "Review duration and timeout errors, including the active versions and aliases, before changing limits or memory.",
)
REGISTRY = metric_registry(
    "lambda", ("lambda:ListFunctions",), "Functions with one current timeout across all published versions",
    ("Duration", "Timeout"), "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html",
    thresholds={"LAMBDA_TIMEOUT_USED_PERCENT": 80}, advisory=True,
)
METRICS = (Metric("Duration", "p95", "Milliseconds"),)


def run(ctx):
    threshold = setting("LAMBDA_TIMEOUT_USED_PERCENT", 80, 1, 100)
    targets = []
    for target in lambda_timeout_targets(ctx):
        if not target.limit:
            yield ctx.finding(META, Status.UNKNOWN, target.arn, "Current timeout is missing or differs between versions.")
            continue
        targets.append(target)

    def evaluate(target, samples):
        value = percentile(samples[0], 0.95)
        timeout = target.limit * 1000
        used = 100 * value / timeout
        return used < threshold, (
            f"95th percentile of hourly p95 duration was {value:.1f} ms, {used:.1f}% of the current "
            f"{timeout:g} ms timeout; review threshold {threshold}%. Timeout may have changed during this window."
        )

    yield from measure(ctx, META, targets, "AWS/Lambda", METRICS, evaluate)

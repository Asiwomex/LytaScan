"""Review the observed share of throttled Lambda invocation requests."""

from scanner.check import CheckMeta, Scope
from scanner.efficiency_metrics import Metric, Target, measure, metric_registry, setting
from scanner.efficiency_resources import lambda_functions
from scanner.findings import Pillar, Severity

V2_ONLY = True
META = CheckMeta(
    "lambda_throttle_pressure", "Lambda invocation throttling exceeds the review threshold",
    Pillar.PERFORMANCE_EFFICIENCY, Severity.MEDIUM, "AWS::Lambda::Function", Scope.REGIONAL,
    "Review reserved concurrency, regional concurrency, scaling and retry behavior for the affected function.",
)
REGISTRY = metric_registry(
    "lambda", ("lambda:ListFunctions",), "Functions with sufficient invocation and throttling metrics",
    ("Throttles", "Invocations"), "https://docs.aws.amazon.com/lambda/latest/dg/monitoring-metrics-types.html",
    thresholds={"LAMBDA_THROTTLE_BASIS_POINTS": 100}, advisory=True,
)
METRICS = (Metric("Throttles", "Sum", "Count"), Metric("Invocations", "Sum", "Count"))


def run(ctx):
    threshold = setting("LAMBDA_THROTTLE_BASIS_POINTS", 100, 1, 10000) / 100
    targets = (
        Target(fn["FunctionArn"], (("FunctionName", fn["FunctionName"]),))
        for fn in lambda_functions(ctx)
    )

    def evaluate(_target, samples):
        throttles, invocations = map(sum, samples)
        if throttles + invocations == 0:
            return None, "No invocation requests were recorded in the measured hours."
        rate = 100 * throttles / (throttles + invocations)
        return rate < threshold, (
            f"{throttles:g} throttled out of {throttles + invocations:g} observed requests "
            f"({rate:.2f}%); review threshold {threshold:g}%."
        )

    yield from measure(ctx, META, targets, "AWS/Lambda", METRICS, evaluate)

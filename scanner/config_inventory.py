"""Read-only configuration inventory helpers for posture rules."""

from collections.abc import Iterator
from typing import Any

from scanner.check import CheckContext, CheckMeta
from scanner.findings import Finding, Status


def items(client: Any, operation: str, result_key: str, **parameters: Any) -> Iterator[dict[str, Any]]:
    """Stream resources across the service's response pages."""
    for page in client.get_paginator(operation).paginate(**parameters):
        yield from page.get(result_key, [])


def flag(
    ctx: CheckContext, meta: CheckMeta, arn: str, observed: Any, *,
    expected: bool, passing: str, failing: str,
) -> Finding:
    """Treat missing or malformed configuration as unavailable evidence."""
    if not isinstance(observed, bool):
        return ctx.finding(meta, Status.UNKNOWN, arn, "AWS did not return a recognized setting.")
    if observed is expected:
        return ctx.finding(meta, Status.PASS, arn, passing)
    return ctx.finding(meta, Status.FAIL, arn, failing)

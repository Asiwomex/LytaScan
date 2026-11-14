"""Discovers the checks in scanner/checks and runs them against an account."""

from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Callable, Iterable, Sequence
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import ModuleType
from typing import Any

import boto3

from scanner import checks as checks_package
from scanner.check import (
    CLIENT_CONFIG,
    GLOBAL_ENDPOINT_REGION,
    GLOBAL_REGION,
    CheckContext,
    CheckMeta,
    Scope,
)
from scanner.findings import Finding, Pillar, Status, format_timestamp
from scanner.coverage import UNAVAILABLE

logger = logging.getLogger(__name__)

# A scan is almost entirely waiting on AWS, so threads speed it up a lot.
# Kept low to stay well under API rate limits.
MAX_WORKERS = 8
LEGACY_PILLARS = frozenset({Pillar.SECURITY, Pillar.RELIABILITY, Pillar.COST})


class CheckDefinitionError(Exception):
    """A module in scanner/checks does not follow the check contract."""


ProgressCallback = Callable[[dict[str, Any]], None]


@dataclass(frozen=True, slots=True)
class Check:
    meta: CheckMeta
    run: Callable[[CheckContext], Iterable[Finding]]
    registry: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanResult:
    account_id: str
    started_at: datetime
    finished_at: datetime
    regions: list[str]
    checks_run: list[str]
    findings: list[Finding]
    assessment: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan": {
                "account_id": self.account_id,
                "started_at": format_timestamp(self.started_at),
                "finished_at": format_timestamp(self.finished_at),
                "regions": self.regions,
                "checks_run": self.checks_run,
                **({"assessment": self.assessment} if self.assessment is not None else {}),
            },
            "findings": [finding.to_dict() for finding in self.findings],
        }


def discover_checks(package: ModuleType = checks_package, *, include_v2: bool = False) -> list[Check]:
    """Import every module in the package and return its check, sorted by id."""
    found: list[Check] = []
    for info in pkgutil.iter_modules(package.__path__):
        module = importlib.import_module(f"{package.__name__}.{info.name}")
        meta = getattr(module, "META", None)
        run = getattr(module, "run", None)
        if not isinstance(meta, CheckMeta) or not callable(run):
            raise CheckDefinitionError(
                f"{module.__name__} must define META (a CheckMeta) and run(ctx)"
            )
        if meta.check_id != info.name:
            raise CheckDefinitionError(
                f"{module.__name__} has check_id {meta.check_id!r}; "
                "the file must be named after its check_id"
            )
        if not include_v2 and (getattr(module, "V2_ONLY", False) or meta.pillar not in LEGACY_PILLARS):
            continue
        found.append(Check(meta=meta, run=run, registry=getattr(module, "REGISTRY", {})))
    return sorted(found, key=lambda check: check.meta.check_id)


def enabled_regions(session: boto3.Session) -> list[str]:
    """Regions the account can use. Opt-in regions that are off are excluded."""
    ec2 = session.client(
        "ec2",
        region_name=session.region_name or GLOBAL_ENDPOINT_REGION,
        config=CLIENT_CONFIG,
    )
    # describe_regions is not a paginated API.
    response = ec2.describe_regions(AllRegions=False)
    return sorted(region["RegionName"] for region in response["Regions"])


def run_check(check: Check, ctx: CheckContext) -> list[Finding]:
    """Run one check. A failure becomes an error finding, never an exception."""
    try:
        return list(check.run(ctx))
    except Exception as exc:  # noqa: BLE001 - one broken check must not stop the scan
        logger.warning("%s failed in %s: %s", check.meta.check_id, ctx.region,
                       type(exc).__name__ if ctx.safe_errors else exc)
        return [ctx.error(check.meta, ctx.account_arn, exc)]


def scope_identity(check: Check, region: str) -> dict[str, str]:
    return {"check_id": check.meta.check_id, "pillar": check.meta.pillar.value, "region": region}


def scope_plan(checks: Sequence[Check], regions: Sequence[str]) -> list[dict[str, str]]:
    return [
        scope_identity(check, region)
        for check in checks
        for region in ([GLOBAL_REGION] if check.meta.scope is Scope.GLOBAL else regions)
    ]


def scope_outcome(check: Check, region: str, results: list[Finding]) -> dict[str, Any]:
    counts = Counter(item.status for item in results)
    reasons = {item.reason_code or "evaluation_unavailable" for item in results if item.status in UNAVAILABLE}
    return {
        **scope_identity(check, region),
        "status": "incomplete" if reasons else "complete",
        "counts": {status.value: counts[status] for status in Status},
        "reason_codes": sorted(reasons),
    }


def _run_scopes(runs, progress: ProgressCallback | None, evaluate):
    """Keep execution bounded and report only the scopes actually dispatched."""
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        if progress is None:
            return list(pool.map(lambda run: evaluate(*run), runs))

        remaining = iter(enumerate(runs))
        results = [[] for _ in runs]
        active = {}

        def dispatch():
            item = next(remaining, None)
            if item is not None:
                index, (check, ctx) = item
                progress({**scope_identity(check, ctx.region), "status": "running"})
                active[pool.submit(evaluate, check, ctx)] = (index, check, ctx.region)

        for _ in range(min(MAX_WORKERS, len(runs))):
            dispatch()
        while active:
            complete, _ = wait(active, return_when=FIRST_COMPLETED)
            for future in complete:
                index, check, region = active.pop(future)
                result = future.result()
                results[index] = result
                progress(scope_outcome(check, region, result))
                dispatch()
        return results


def run_scan(
    session: boto3.Session,
    checks: Sequence[Check] | None = None,
    regions: Sequence[str] | None = None,
    now: datetime | None = None,
    *,
    version: int = 1,
    evaluation_filter: Callable[[Finding], bool] | None = None,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Run every check against the account the session's credentials belong to."""
    started_at = now or datetime.now(timezone.utc)
    checks = discover_checks(include_v2=version == 2) if checks is None else checks

    sts = session.client(
        "sts",
        region_name=session.region_name or GLOBAL_ENDPOINT_REGION,
        config=CLIENT_CONFIG,
    )
    account_id: str = sts.get_caller_identity()["Account"]

    # Only look up regions when a check needs them, so an IAM-only scan does
    # not depend on ec2:DescribeRegions.
    has_regional_checks = any(check.meta.scope is Scope.REGIONAL for check in checks)
    if not has_regional_checks:
        scan_regions: list[str] = []
    elif regions is None:
        scan_regions = enabled_regions(session)
    else:
        scan_regions = list(regions)

    runs: list[tuple[Check, CheckContext]] = []
    for check in checks:
        targets = [GLOBAL_REGION] if check.meta.scope is Scope.GLOBAL else scan_regions
        for region in targets:
            ctx = CheckContext(
                session=session, account_id=account_id, region=region, now=started_at, safe_errors=version == 2
            )
            runs.append((check, ctx))

    def run_scope(check: Check, ctx: CheckContext) -> list[Finding]:
        results = run_check(check, ctx)
        if evaluation_filter is None:
            return results
        selected = [item for item in results if evaluation_filter(item)
                    or (item.status == Status.ERROR and item.resource_arn == ctx.account_arn)]
        if not selected:
            selected.append(ctx.finding(
                check.meta, Status.UNKNOWN, ctx.account_arn,
                "The selected resource could not be evaluated.", reason_code="resource_not_evaluated",
            ))
        return selected

    findings = []
    scopes = []
    for (check, ctx), result in zip(runs, _run_scopes(runs, progress, run_scope), strict=True):
        findings.extend(result)
        if version == 2:
            outcome = scope_outcome(check, ctx.region, result)
            outcome["outcome"] = outcome.pop("status")
            scopes.append(outcome)

    score = None
    if version == 2:
        from scanner.coverage import assessment
        from scanner.registry import REGISTRY_VERSION

        score = {**assessment(findings, scopes), "registry_version": REGISTRY_VERSION, "scopes": scopes}

    return ScanResult(
        account_id=account_id,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc) if now is None else now,
        regions=scan_regions,
        checks_run=[check.meta.check_id for check in checks],
        findings=findings,
        assessment=score,
    )

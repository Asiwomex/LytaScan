"""Coverage and versioned scoring for v2 reports."""

from collections import Counter
from collections.abc import Sequence
from typing import Any

from scanner.findings import Finding, Pillar, Status

SCORE_VERSION = "2.0.0"
WEIGHTS = {"critical": 10, "high": 5, "medium": 3, "low": 1}
EVALUATED = {Status.PASS, Status.FAIL}
UNAVAILABLE = {Status.ERROR, Status.UNKNOWN, Status.SKIPPED}


def assessment(findings: Sequence[Finding], scopes: Sequence[dict[str, Any]]) -> dict[str, Any]:
    pillars = []
    scores = []
    for pillar in Pillar:
        own = [item for item in findings if item.pillar == pillar]
        counts = Counter(item.status for item in own)
        weight = sum(WEIGHTS[item.severity] for item in own if item.status in EVALUATED)
        passed = sum(WEIGHTS[item.severity] for item in own if item.status == Status.PASS)
        score = 100 * passed / weight if weight else None
        if score is not None:
            scores.append(score)
        evaluated = sum(counts[status] for status in EVALUATED)
        unavailable = sum(counts[status] for status in UNAVAILABLE)
        own_scopes = [scope for scope in scopes if scope["pillar"] == pillar]
        pillars.append({
            "pillar": pillar.value, "score": round(score, 2) if score is not None else None,
            "evaluated": evaluated, "unavailable": unavailable,
            "coverage": round(100 * evaluated / (evaluated + unavailable), 2) if evaluated + unavailable else None,
            "planned_scopes": len(own_scopes),
            "completed_scopes": sum(scope["outcome"] == "complete" for scope in own_scopes),
        })
    return {
        "version": SCORE_VERSION, "overall_score": round(sum(scores) / len(scores), 2) if scores else None,
        "evaluated_pillars": len(scores), "pillars": pillars,
        "planned_scopes": len(scopes), "completed_scopes": sum(scope["outcome"] == "complete" for scope in scopes),
        "critical_failures": sum(item.status == Status.FAIL and item.severity == "critical" for item in findings),
    }

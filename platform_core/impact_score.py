"""Explainable reliability impact scoring."""

from __future__ import annotations

from platform_core.reasoning_models import (
    ImpactDuration,
    ImpactScope,
    ImpactSeverity,
    ReliabilityImpact,
)

SEVERITY_WEIGHTS: dict[ImpactSeverity, float] = {
    "low": 0.25,
    "medium": 0.55,
    "high": 0.85,
    "critical": 1.0,
}
SCOPE_WEIGHTS: dict[ImpactScope, float] = {
    "browser_only": 0.65,
    "dev_tools": 0.55,
    "browser_and_dev_tools": 0.90,
    "system_wide": 1.0,
    "multi_endpoint": 1.0,
}
DURATION_WEIGHTS: dict[ImpactDuration, float] = {
    "short": 0.65,
    "medium": 0.85,
    "long": 1.0,
    "unknown": 0.85,
}


def impact_level(score: float) -> ImpactSeverity:
    """Convert score to an impact level."""
    if score >= 0.75:
        return "critical"
    if score >= 0.50:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


def calculate_reliability_impact(
    *,
    severity: ImpactSeverity,
    scope: ImpactScope,
    confidence: float,
    duration_factor: ImpactDuration = "unknown",
) -> ReliabilityImpact:
    """Calculate a simple explainable reliability impact score.

    Args:
        severity: User-visible severity bucket.
        scope: Affected workflow scope.
        confidence: Ordinal confidence ranking in ``0..1``.
        duration_factor: Coarse duration bucket.

    Returns:
        Reliability impact model with score and explanation.
    """
    bounded_confidence = max(0.0, min(1.0, confidence))
    score = (
        SEVERITY_WEIGHTS[severity]
        * SCOPE_WEIGHTS[scope]
        * bounded_confidence
        * DURATION_WEIGHTS[duration_factor]
    )
    score = round(max(0.0, min(1.0, score)), 2)
    level = impact_level(score)
    return ReliabilityImpact(
        severity=severity,
        scope=scope,
        confidence=bounded_confidence,
        duration_factor=duration_factor,
        impact_score=score,
        impact_level=level,
        explanation=(
            f"Impact uses severity={severity}, scope={scope}, confidence={bounded_confidence:.2f}, "
            f"duration={duration_factor}. The score is a ranking aid, not a financial loss model."
        ),
        limitations=[
            "Impact score is ordinal and explainable; it is not a calibrated outage probability."
        ],
        recommended_next_steps=[
            "Validate user-visible workflow impact before executing remediation."
        ],
    )

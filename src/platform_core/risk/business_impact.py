"""Business impact estimation for risk triage — decision support, not financial advice."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_DEFAULT_LIMITATIONS = [
    "Ordinal impact scores for triage — not accounting-grade loss estimation.",
    "Not financial advice; does not replace business continuity planning.",
    "Classification is not accusation; impact reflects operational disruption scope.",
]


class BusinessImpactEstimate(BaseModel):
    """Represent the business impact estimate type.

    Key fields:
        downtime_minutes: Structured value carried by this type.
        affected_users: Structured value carried by this type.
        estimated_cost_per_hour: Structured value carried by this type.
        operational_impact_score: Structured value carried by this type.
        compliance_impact_score: Structured value carried by this type.
        reputational_impact_score: Structured value carried by this type.
        total_business_impact_score: Structured value carried by this type.
        confidence_type: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    downtime_minutes: int = 0
    affected_users: int = 0
    estimated_cost_per_hour: float = 0.0
    operational_impact_score: int = Field(default=1, ge=1, le=5)
    compliance_impact_score: int = Field(default=1, ge=1, le=5)
    reputational_impact_score: int = Field(default=1, ge=1, le=5)
    total_business_impact_score: int = Field(default=1, ge=1, le=5)
    confidence_type: str = "ordinal_not_probability"
    limitations: list[str] = Field(default_factory=lambda: list(_DEFAULT_LIMITATIONS))


_CLASSIFICATION_IMPACT = {
    "DEAD_PROXY_CONFIG": (3, 2, 1, 30, 25),
    "UNKNOWN_LOCAL_PROXY": (3, 3, 2, 45, 50),
    "POSSIBLE_MITM_RISK": (4, 4, 4, 60, 100),
    "SUSPICIOUS_PROXY": (3, 3, 3, 45, 75),
    "TLS_MISMATCH": (4, 3, 3, 60, 80),
    "HEALTHY": (1, 1, 1, 0, 0),
}


def estimate_business_impact(
    *,
    classification: str | None = None,
    evidence_tier: str | None = None,
    affected_users: int | None = None,
    downtime_minutes: int | None = None,
    estimated_cost_per_hour: float | None = None,
    fixture: dict[str, Any] | None = None,
) -> BusinessImpactEstimate:
    """Estimate ordinal business impact from classification and optional fixture context."""
    cls = (classification or "").upper()
    if fixture:
        classification_block = fixture.get("classification") or {}
        cls = cls or str(classification_block.get("primary_classification") or "").upper()
        if affected_users is None:
            affected_users = int(
                fixture.get("affected_users") or classification_block.get("affected_users") or 0
            )
        if downtime_minutes is None:
            downtime_minutes = int(fixture.get("downtime_minutes") or 0)

    defaults = _CLASSIFICATION_IMPACT.get(cls, (2, 2, 2, 30, 40))
    op, comp, rep, default_downtime, default_users = defaults

    tier = (evidence_tier or "").lower()
    if tier in ("observation", "observed_only"):
        op = max(1, op - 1)
    elif tier in ("proof", "final_causation"):
        op = min(5, op + 1)

    downtime = downtime_minutes if downtime_minutes is not None else default_downtime
    users = affected_users if affected_users is not None else default_users
    cost = estimated_cost_per_hour if estimated_cost_per_hour is not None else 150.0

    total = min(5, max(1, round((op + comp + rep) / 3)))
    limitations = list(_DEFAULT_LIMITATIONS)
    if cls in ("POSSIBLE_MITM_RISK", "SUSPICIOUS_PROXY"):
        limitations.append("Security-adjacent label — triage context only, not malware verdict.")

    return BusinessImpactEstimate(
        downtime_minutes=downtime,
        affected_users=users,
        estimated_cost_per_hour=cost,
        operational_impact_score=op,
        compliance_impact_score=comp,
        reputational_impact_score=rep,
        total_business_impact_score=total,
        limitations=limitations,
    )

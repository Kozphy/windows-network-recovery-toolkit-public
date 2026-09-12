"""Deterministic benefit / risk / confidence scoring for candidate decisions.

Pipeline (explicit, no black-box):
    Evidence → Candidate Decision → Benefit → Risk → Confidence → Final Score

Legacy v1 root-cause scoring remains importable from this module for backward compatibility.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# Transparent constants — all formulas reference these by name in breakdown output.
BENEFIT_EVIDENCE_SCALE = 40.0
RISK_EVIDENCE_SCALE = 35.0
FINAL_RISK_PENALTY = 0.35
CONFIDENCE_COVERAGE_WEIGHT = 0.5

FINAL_SCORE_FORMULA = (
    "final_score = clamp(round(benefit * confidence - risk * "
    f"{FINAL_RISK_PENALTY}), 0, 100)"
)
CONFIDENCE_FORMULA = (
    "confidence = support_ratio * ("
    f"{CONFIDENCE_COVERAGE_WEIGHT} + {CONFIDENCE_COVERAGE_WEIGHT} * evidence_coverage)"
)


def _clamp_int(value: float, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, int(round(value))))


def _clamp_confidence(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 4)


class EvidenceItem(BaseModel):
    """Normalized evidence input for scoring."""

    evidence_id: str
    label: str
    weight: float = Field(default=0.5, ge=0.0, le=1.0)
    supports_decision: bool = True
    detail: str = ""


class CandidateDecision(BaseModel):
    """A decision option evaluated against shared evidence."""

    decision_id: str
    label: str
    base_benefit: float = Field(default=50.0, ge=0.0, le=100.0)
    base_risk: float = Field(default=15.0, ge=0.0, le=100.0)
    evidence_relevance: dict[str, float] = Field(default_factory=dict)
    risk_factors: dict[str, float] = Field(default_factory=dict)


class ScoreBreakdown(BaseModel):
    """Explainable decomposition of every score component."""

    benefit_components: dict[str, float] = Field(default_factory=dict)
    risk_components: dict[str, float] = Field(default_factory=dict)
    confidence_components: dict[str, float] = Field(default_factory=dict)
    benefit: int = Field(ge=0, le=100)
    risk: int = Field(ge=0, le=100)
    confidence: float = Field(ge=0.0, le=1.0)
    final_score: int = Field(ge=0, le=100)
    formulas: dict[str, str] = Field(default_factory=dict)


class ScoredDecision(BaseModel):
    """One candidate decision after deterministic scoring."""

    decision_id: str
    decision: str
    confidence: float = Field(ge=0.0, le=1.0)
    benefit: int = Field(ge=0, le=100)
    risk: int = Field(ge=0, le=100)
    final_score: int = Field(ge=0, le=100)
    breakdown: ScoreBreakdown
    recommendation: str = ""


def _relevance(candidate: CandidateDecision, evidence_id: str) -> float:
    if not candidate.evidence_relevance:
        return 1.0
    return float(candidate.evidence_relevance.get(evidence_id, 0.0))


def score_candidate(
    evidence: list[EvidenceItem],
    candidate: CandidateDecision,
) -> ScoredDecision:
    """Score one candidate decision against evidence (deterministic).

    Args:
        evidence: Shared evidence snapshot.
        candidate: One decision option with base scores and relevance map.

    Returns:
        :class:`ScoredDecision` with explainable ``breakdown`` and recommendation text.

    Audit Notes:
        Formula constants (``BENEFIT_EVIDENCE_SCALE``, etc.) are referenced in breakdown
        output — change only with replay digest verification.
    """
    benefit_parts: dict[str, float] = {"base_benefit": candidate.base_benefit}
    risk_parts: dict[str, float] = {"base_risk": candidate.base_risk}

    supporting_weight = 0.0
    total_weight = 0.0
    matched_evidence = 0

    for item in evidence:
        rel = _relevance(candidate, item.evidence_id)
        if rel <= 0.0:
            continue
        matched_evidence += 1
        total_weight += item.weight * rel
        contribution = item.weight * rel
        if item.supports_decision:
            supporting_weight += contribution
            benefit_parts[f"evidence:{item.evidence_id}"] = contribution * BENEFIT_EVIDENCE_SCALE
        else:
            risk_parts[f"evidence:{item.evidence_id}"] = contribution * RISK_EVIDENCE_SCALE

    for name, value in sorted(candidate.risk_factors.items()):
        risk_parts[f"risk_factor:{name}"] = float(value)

    benefit_raw = sum(benefit_parts.values())
    risk_raw = sum(risk_parts.values())
    benefit = _clamp_int(benefit_raw)
    risk = _clamp_int(risk_raw)

    support_ratio = supporting_weight / total_weight if total_weight > 0 else 0.0
    evidence_coverage = matched_evidence / len(evidence) if evidence else 0.0
    confidence = _clamp_confidence(
        support_ratio * (CONFIDENCE_COVERAGE_WEIGHT + CONFIDENCE_COVERAGE_WEIGHT * evidence_coverage)
    )

    confidence_parts = {
        "support_ratio": round(support_ratio, 4),
        "evidence_coverage": round(evidence_coverage, 4),
        "supporting_weight": round(supporting_weight, 4),
        "total_weight": round(total_weight, 4),
    }

    final_score = _clamp_int(benefit * confidence - risk * FINAL_RISK_PENALTY)

    breakdown = ScoreBreakdown(
        benefit_components={k: round(v, 4) for k, v in sorted(benefit_parts.items())},
        risk_components={k: round(v, 4) for k, v in sorted(risk_parts.items())},
        confidence_components=confidence_parts,
        benefit=benefit,
        risk=risk,
        confidence=confidence,
        final_score=final_score,
        formulas={
            "benefit": "benefit = clamp(round(sum(benefit_components)), 0, 100)",
            "risk": "risk = clamp(round(sum(risk_components)), 0, 100)",
            "confidence": CONFIDENCE_FORMULA,
            "final_score": FINAL_SCORE_FORMULA,
        },
    )

    recommendation = _recommendation_text(candidate.label, final_score, confidence, risk)

    return ScoredDecision(
        decision_id=candidate.decision_id,
        decision=candidate.label,
        confidence=confidence,
        benefit=benefit,
        risk=risk,
        final_score=final_score,
        breakdown=breakdown,
        recommendation=recommendation,
    )


def score_candidates(
    evidence: list[EvidenceItem],
    candidates: list[CandidateDecision],
) -> list[ScoredDecision]:
    """Score all candidates; output order follows input order.

    Args:
        evidence: Shared evidence snapshot.
        candidates: Decision options to evaluate.

    Returns:
        Scored list in input order — call :func:`ranking.rank_scored_decisions` to sort.
    """
    return [score_candidate(evidence, candidate) for candidate in candidates]


def scored_to_payload(scored: ScoredDecision) -> dict[str, Any]:
    """Primary API output shape plus nested breakdown."""
    return {
        "decision": scored.decision,
        "decision_id": scored.decision_id,
        "confidence": scored.confidence,
        "benefit": scored.benefit,
        "risk": scored.risk,
        "final_score": scored.final_score,
        "recommendation": scored.recommendation,
        "breakdown": scored.breakdown.model_dump(mode="json"),
    }


def _recommendation_text(label: str, final_score: int, confidence: float, risk: int) -> str:
    if final_score >= 70 and confidence >= 0.7 and risk <= 30:
        return f"Recommend '{label}' — strong benefit with acceptable risk."
    if final_score >= 50 and confidence >= 0.5:
        return f"Consider '{label}' — moderate score; review breakdown before action."
    if risk >= 60:
        return f"Defer '{label}' — elevated risk; gather more evidence."
    return f"Monitor '{label}' — low confidence or weak final score."


# Legacy v1 root-cause scoring (unchanged import path).
from .legacy_scoring import (  # noqa: E402
    ALL_CAUSES,
    CauseScore,
    DecisionResult,
    RootCauseKey,
    explain_primary,
    score_root_causes,
)

__all__ = [
    "ALL_CAUSES",
    "BENEFIT_EVIDENCE_SCALE",
    "CONFIDENCE_FORMULA",
    "FINAL_RISK_PENALTY",
    "FINAL_SCORE_FORMULA",
    "RISK_EVIDENCE_SCALE",
    "CandidateDecision",
    "CauseScore",
    "DecisionResult",
    "EvidenceItem",
    "RootCauseKey",
    "ScoreBreakdown",
    "ScoredDecision",
    "explain_primary",
    "score_candidate",
    "score_candidates",
    "score_root_causes",
    "scored_to_payload",
]

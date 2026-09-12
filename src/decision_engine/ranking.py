"""Deterministic ranking of scored candidate decisions."""

from __future__ import annotations

from pydantic import BaseModel, Field

from .scoring import ScoredDecision, scored_to_payload


class RankedDecision(BaseModel):
    """Scored decision with explicit rank for replay and audit."""

    rank: int = Field(ge=1)
    decision_id: str
    decision: str
    confidence: float
    benefit: int
    risk: int
    final_score: int
    recommendation: str
    breakdown: dict[str, object] = Field(default_factory=dict)


def rank_scored_decisions(scored: list[ScoredDecision]) -> list[RankedDecision]:
    """Rank scored candidates with deterministic tie-breaking.

    Sort order: ``final_score`` descending, ``confidence`` descending,
    ``decision_id`` ascending.

    Args:
        scored: Scored decisions from :func:`scoring.score_candidates`.

    Returns:
        Ranked list with 1-based ``rank`` fields.
    """
    ordered = sorted(
        scored,
        key=lambda row: (-row.final_score, -row.confidence, row.decision_id),
    )
    ranked: list[RankedDecision] = []
    for index, row in enumerate(ordered, start=1):
        payload = scored_to_payload(row)
        ranked.append(
            RankedDecision(
                rank=index,
                decision_id=row.decision_id,
                decision=row.decision,
                confidence=row.confidence,
                benefit=row.benefit,
                risk=row.risk,
                final_score=row.final_score,
                recommendation=row.recommendation,
                breakdown=payload["breakdown"],  # type: ignore[arg-type]
            )
        )
    return ranked


def top_ranked(scored: list[ScoredDecision]) -> RankedDecision | None:
    """Return the highest-ranked decision or ``None`` when no candidates exist."""
    ranked = rank_scored_decisions(scored)
    return ranked[0] if ranked else None

"""Decision Intelligence scoring engine — evidence to ranked recommendation (deterministic).

System placement:
    - Core math shared by Windows toolkit, market events, and multi-domain adapters.
    - Invoked via :func:`run_decision_engine` and bridged by
      :mod:`platform_core.decision_platform.reasoning`.

Pipeline::

    EvidenceItem[] + CandidateDecision[] → score → rank → digest

Key invariants:
    - No ML, no randomness — identical inputs yield identical ``content_digest``.
    - Digest covers evidence JSON and ranked payload only (not observation timestamps).

Failure modes:
    - ``ValueError`` when candidate list is empty.
    - ``KeyError`` when internal rank lookup misses a decision_id (should not occur).

Audit Notes:
    Replay ``content_digest`` before changing scoring constants in :mod:`scoring`.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, Field

from .ranking import rank_scored_decisions, top_ranked
from .scoring import (
    CandidateDecision,
    EvidenceItem,
    ScoredDecision,
    score_candidates,
    scored_to_payload,
)


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def content_digest(payload: Any) -> str:
    """Compute SHA-256 digest over canonical JSON for replay and audit integrity.

    Args:
        payload: JSON-serializable object (dict/list/scalars).

    Returns:
        Lowercase hex SHA-256 string (64 characters).

    Notes:
        Uses sorted keys and compact separators for deterministic serialization.
    """
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


class DecisionEngineResult(BaseModel):
    """Full engine output: top recommendation, ranking, and replay digest."""

    recommendation: dict[str, Any]
    ranked: list[dict[str, Any]] = Field(default_factory=list)
    evidence_count: int = 0
    candidate_count: int = 0
    content_digest: str = ""


def run_decision_engine(
    evidence: list[EvidenceItem],
    candidates: list[CandidateDecision],
) -> DecisionEngineResult:
    """Evaluate evidence against candidates and return ranked recommendations.

    Args:
        evidence: Normalized evidence items for scoring.
        candidates: Decision options with base benefit/risk and relevance maps.

    Returns:
        Top recommendation, full ranking, counts, and ``content_digest``.

    Raises:
        ValueError: If ``candidates`` is empty.

    Side effects:
        None — pure deterministic computation.
    """
    if not candidates:
        raise ValueError("at least one candidate decision is required")

    scored = score_candidates(evidence, candidates)
    ranked = rank_scored_decisions(scored)
    top = top_ranked(scored)
    assert top is not None

    ranked_payload = [
        {
            "rank": row.rank,
            **scored_to_payload(_scored_by_id(scored, row.decision_id)),
        }
        for row in ranked
    ]

    recommendation = {
        "rank": top.rank,
        **scored_to_payload(_scored_by_id(scored, top.decision_id)),
    }

    digest = content_digest(
        {
            "evidence": [e.model_dump(mode="json") for e in evidence],
            "ranked": ranked_payload,
        }
    )

    return DecisionEngineResult(
        recommendation=recommendation,
        ranked=ranked_payload,
        evidence_count=len(evidence),
        candidate_count=len(candidates),
        content_digest=digest,
    )


def _scored_by_id(scored: list[ScoredDecision], decision_id: str) -> ScoredDecision:
    for row in scored:
        if row.decision_id == decision_id:
            return row
    raise KeyError(decision_id)


def engine_summary(result: DecisionEngineResult) -> dict[str, Any]:
    """Build a compact summary dict from a full engine result.

    Args:
        result: Output of :func:`run_decision_engine`.

    Returns:
        Dict with keys ``decision``, ``confidence``, ``benefit``, ``risk``,
        ``final_score``, ``recommendation``, ``breakdown``, ``content_digest``.
    """
    rec = result.recommendation
    return {
        "decision": rec["decision"],
        "confidence": rec["confidence"],
        "benefit": rec["benefit"],
        "risk": rec["risk"],
        "final_score": rec["final_score"],
        "recommendation": rec["recommendation"],
        "breakdown": rec["breakdown"],
        "content_digest": result.content_digest,
    }

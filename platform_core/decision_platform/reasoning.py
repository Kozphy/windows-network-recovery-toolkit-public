"""Shared reasoning engine bridge — all domains use ``src.decision_engine``.

System placement:
    - Called by :meth:`platform_core.decision_platform.adapter.DomainAdapter.evaluate`.
    - Single entry point ensuring every domain shares identical scoring/ranking logic.

Key invariants:
    - No domain-specific scoring forks — all math lives in :mod:`src.decision_engine`.
    - ``engine_digest`` is SHA-256 over canonical JSON of evidence + ranked candidates.
    - Observations are carried through for audit but do not affect digest directly.

Failure modes:
    - ``ValueError`` when ``candidate_specs`` is empty.
    - Engine ``KeyError`` if ranked payload references a missing decision_id (internal).

Audit Notes:
    Compare ``engine_digest`` across replays before promoting scoring constant changes.
    Digest stability requires stable ``evidence_id`` values on adapter evidence rows.
"""

from __future__ import annotations

from typing import Any

from src.decision_engine import CandidateDecision, EvidenceItem, engine_summary, run_decision_engine

from .models import Decision, DomainPipelineResult, Evidence, Observation, PlatformDomain


def _to_engine_evidence(evidence: list[Evidence]) -> list[EvidenceItem]:
    """Map platform evidence models to engine scoring inputs."""
    return [
        EvidenceItem(
            evidence_id=row.evidence_id,
            label=row.label,
            weight=row.weight,
            supports_decision=row.supports_decision,
            detail=row.detail,
        )
        for row in evidence
    ]


def _to_engine_candidates(specs: list[dict[str, Any]]) -> list[CandidateDecision]:
    """Map adapter candidate spec dicts to engine :class:`CandidateDecision` rows."""
    candidates: list[CandidateDecision] = []
    for index, spec in enumerate(specs):
        candidates.append(
            CandidateDecision(
                decision_id=spec.get("decision_id", f"candidate_{index}"),
                label=spec["label"],
                base_benefit=float(spec.get("base_benefit", 50.0)),
                base_risk=float(spec.get("base_risk", 15.0)),
                evidence_relevance=dict(spec.get("evidence_relevance", {})),
                risk_factors=dict(spec.get("risk_factors", {})),
            )
        )
    return candidates


def run_shared_reasoning(
    *,
    domain: PlatformDomain,
    observations: list[Observation],
    evidence: list[Evidence],
    candidate_specs: list[dict[str, Any]],
) -> DomainPipelineResult:
    """Execute the shared decision engine and map results to unified models.

    Args:
        domain: Platform domain being evaluated.
        observations: Collected observations (audit trail).
        evidence: Derived evidence passed to scoring.
        candidate_specs: Adapter-defined candidate decisions.

    Returns:
        :class:`DomainPipelineResult` with decision, alternatives, and digest.

    Raises:
        ValueError: If ``candidate_specs`` is empty.
    """
    if not candidate_specs:
        raise ValueError("at least one candidate decision spec is required")

    engine_result = run_decision_engine(_to_engine_evidence(evidence), _to_engine_candidates(candidate_specs))
    summary = engine_summary(engine_result)
    rec = engine_result.recommendation
    decision = Decision(
        decision_id=str(rec.get("decision_id", f"dec_{domain.value}")),
        domain=domain.value,
        title=summary["decision"],
        confidence=float(summary["confidence"]),
        benefit=int(summary["benefit"]),
        risk=int(summary["risk"]),
        final_score=int(summary["final_score"]),
        recommendation=str(summary.get("recommendation", "")),
        content_digest=str(summary.get("content_digest", engine_result.content_digest)),
    )
    return DomainPipelineResult(
        domain=domain.value,
        observations=observations,
        evidence=evidence,
        decision=decision,
        alternatives=list(engine_result.ranked),
        engine_digest=engine_result.content_digest,
    )

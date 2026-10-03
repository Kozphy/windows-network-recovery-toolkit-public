"""Unified evidence fusion and hypothesis ranking (all domains)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.platform.models import EvidenceItem, Hypothesis, NormalizedEvent


@dataclass
class EvidenceTreeNode:
    """Represent evidence tree node data used by the toolkit.

    Attributes:
        evidence_id: Field or variant describing evidence id evidence or state.
        description: Field or variant describing description evidence or state.
        type: Field or variant describing type evidence or state.
        confidence_delta: Field or variant describing confidence delta evidence or state.
        supports: Field or variant describing supports evidence or state.
        contradicts: Field or variant describing contradicts evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    evidence_id: str
    description: str
    type: str
    confidence_delta: float
    supports: list[str]
    contradicts: list[str]


@dataclass
class EvidenceEngineResult:
    """Represent evidence engine result data used by the toolkit.

    Attributes:
        ranked_hypotheses: Field or variant describing ranked hypotheses evidence or state.
        confidence_score: Field or variant describing confidence score evidence or state.
        evidence_tree: Field or variant describing evidence tree evidence or state.
        supporting_evidence: Field or variant describing supporting evidence evidence or state.
        contradicting_evidence: Field or variant describing contradicting evidence evidence or state.
        explanation: Field or variant describing explanation evidence or state.
        metadata: Field or variant describing metadata evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    ranked_hypotheses: list[Hypothesis]
    confidence_score: float
    evidence_tree: list[EvidenceTreeNode]
    supporting_evidence: list[str]
    contradicting_evidence: list[str]
    explanation: str
    metadata: dict[str, Any] = field(default_factory=dict)


def _clamp(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 4)


def rank_hypotheses(
    event: NormalizedEvent,
    evidence: list[EvidenceItem],
    hypotheses: list[Hypothesis],
) -> EvidenceEngineResult:
    """Rank hypotheses.

    Args:
        event: Evidence or domain record being processed.
        evidence: The evidence value supplied by the caller.
        hypotheses: The hypotheses value supplied by the caller.

    Returns:
        The EvidenceEngineResult result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    by_id = {e.evidence_id: e for e in evidence}
    tree = [
        EvidenceTreeNode(
            evidence_id=e.evidence_id,
            description=e.description,
            type=e.type,
            confidence_delta=e.confidence_delta,
            supports=list(e.supports),
            contradicts=list(e.contradicts),
        )
        for e in evidence
    ]
    ranked: list[Hypothesis] = []
    notes: list[str] = []
    supporting: set[str] = set()
    contradicting: set[str] = set()

    for hyp in hypotheses:
        support_delta = 0.0
        contra_delta = 0.0
        for eid in hyp.supporting_evidence:
            item = by_id.get(eid)
            if item:
                support_delta += max(0.0, item.confidence_delta)
                supporting.add(eid)
        for eid in hyp.contradicting_evidence:
            item = by_id.get(eid)
            if item:
                contra_delta += abs(item.confidence_delta)
                contradicting.add(eid)
        missing = sum(1 for eid in hyp.supporting_evidence if eid not in by_id)
        adjusted = _clamp(hyp.confidence + support_delta - contra_delta - 0.05 * missing)
        notes.append(f"{hyp.hypothesis_id}=>{adjusted:.2f}")
        ranked.append(hyp.model_copy(update={"confidence": adjusted}))

    ranked.sort(key=lambda h: (-h.confidence, h.hypothesis_id))
    top = ranked[0].confidence if ranked else 0.3
    if not evidence:
        top = _clamp(top - 0.15)

    return EvidenceEngineResult(
        ranked_hypotheses=ranked,
        confidence_score=top,
        evidence_tree=tree,
        supporting_evidence=sorted(supporting),
        contradicting_evidence=sorted(contradicting),
        explanation=f"Event {event.event_id}: {'; '.join(notes[:3])}",
        metadata={"event_id": event.event_id, "domain": event.domain},
    )

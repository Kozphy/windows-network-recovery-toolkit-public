"""Unified deterministic replay for Multi-Domain Decision Platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.platform.audit import audit_pipeline_step
from src.platform.decision_engine import RankedDecision, rank_decisions
from src.platform.domains.base import DomainAdapter
from src.platform.domains.fixture_graph import load_decisions, load_hypotheses
from src.platform.evidence_engine import EvidenceEngineResult, rank_hypotheses
from src.platform.models import (
    DecisionOption,
    DecisionOutcome,
    EvidenceItem,
    Hypothesis,
    NormalizedEvent,
)
from src.platform.policy_engine import apply_policy
from src.platform.registry import all_adapters
from src.platform.serialization import canonical_json, content_hash


@dataclass
class PipelineResult:
    """Represent pipeline result data used by the toolkit.

    Attributes:
        event: Field or variant describing event evidence or state.
        evidence: Field or variant describing evidence evidence or state.
        hypotheses: Field or variant describing hypotheses evidence or state.
        evidence_result: Field or variant describing evidence result evidence or state.
        decisions: Field or variant describing decisions evidence or state.
        ranked_decisions: Field or variant describing ranked decisions evidence or state.
        top_decision: Field or variant describing top decision evidence or state.
        outcome: Field or variant describing outcome evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    event: NormalizedEvent
    evidence: list[EvidenceItem]
    hypotheses: list[Hypothesis]
    evidence_result: EvidenceEngineResult
    decisions: list[DecisionOption]
    ranked_decisions: list[RankedDecision]
    top_decision: DecisionOption | None
    outcome: DecisionOutcome | None = None
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def run_pipeline(
    adapter: DomainAdapter,
    *,
    fixture_name: str | None = None,
    audit_path: Path | None = None,
    command: str = "replay",
    record_audit: bool = True,
) -> PipelineResult:
    """Event → Evidence → Hypothesis → Decision → Policy → (optional) audit."""
    event = adapter.collect_events(fixture_name)[0]
    evidence = adapter.build_evidence(event)
    hypotheses = load_hypotheses(adapter, event)
    evidence_result = rank_hypotheses(event, evidence, hypotheses)
    raw_decisions = load_decisions(adapter, event)
    gated = apply_policy(event, raw_decisions, confidence=evidence_result.confidence_score)
    ranked = rank_decisions(event, evidence_result.ranked_hypotheses, evidence, gated)
    top = ranked[0].decision if ranked else None

    payload = {
        "event_id": event.event_id,
        "evidence_count": len(evidence),
        "top_hypothesis": evidence_result.ranked_hypotheses[0].hypothesis_id
        if evidence_result.ranked_hypotheses
        else None,
        "top_decision": top.decision_id if top else None,
        "top_score": top.final_score if top else 0.0,
    }
    fingerprint = content_hash(payload)

    if record_audit and top:
        audit_pipeline_step(
            domain=event.domain,
            event_id=event.event_id,
            command=command,
            input_payload={"event": event.model_dump(mode="json"), "fixture": fixture_name},
            output_payload=payload,
            policy_status=top.policy_status,
            explanation=top.explanation or evidence_result.explanation,
            timestamp_utc=event.timestamp_utc,
            path=audit_path,
        )

    return PipelineResult(
        event=event,
        evidence=evidence,
        hypotheses=hypotheses,
        evidence_result=evidence_result,
        decisions=gated,
        ranked_decisions=ranked,
        top_decision=top,
        fingerprint=fingerprint,
        metadata={"canonical_preview": canonical_json(payload)},
    )


def replay_all(*, audit_path: Path | None = None) -> list[PipelineResult]:
    """Replay all.

    Args:
        audit_path: Filesystem path used by the operation.

    Returns:
        The list[PipelineResult] result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    results: list[PipelineResult] = []
    for adapter in all_adapters():
        for fname in adapter.list_fixtures():
            results.append(
                run_pipeline(adapter, fixture_name=fname, audit_path=audit_path, command="replay")
            )
    return results


def find_event(event_id: str) -> tuple[DomainAdapter, str]:
    """Find event.

    Args:
        event_id: The event id value supplied by the caller.

    Returns:
        The tuple[DomainAdapter, str] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    for adapter in all_adapters():
        for fname in adapter.list_fixtures():
            for ev in adapter.collect_events(fname):
                if ev.event_id == event_id:
                    return adapter, fname
    raise KeyError(f"Unknown event_id: {event_id}")

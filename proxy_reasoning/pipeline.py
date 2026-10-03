"""Proxy attribute reasoning pipeline: Signal → Event → Hypothesis → Verification → Policy.

Module responsibility:
    Orchestrate ranking, verification, confidence boundary, and policy evaluation into a
    ``ProxyReasoningRun`` suitable for audit append or replay.

System placement:
    Primary entry for programmatic proxy reasoning; called by ``audit.replay_proxy_reasoning_record``.

Input assumptions:
    ``payload`` dict is collector-shaped (WinINET/WinHTTP/listener fields) unless replaying audit.

Output guarantees:
    ``ProxyReasoningRun`` includes ``policy_decision``, ``limitations``, and ``user_visible_summary``.

Side effects:
    None in this module (callers append audit separately).

Audit Notes:
    * Replay path reuses stored signals — does not re-probe the network.
    * Policy outcome is independent of diagnosis text; verify both before executing remediation.
"""

from __future__ import annotations

from typing import Any

from platform_core.models import utc_now_iso
from proxy_reasoning.constants import ENGINE_VERSION, SCHEMA_VERSION
from proxy_reasoning.models import (
    ConfidenceBoundary,
    EvidenceAttributes,
    EvidenceItem,
    ProxyEntity,
    ProxyReasoningRun,
    ProxySignal,
)
from proxy_reasoning.policy import evaluate_proxy_policy
from proxy_reasoning.scenarios import rank_hypotheses
from proxy_reasoning.verification import run_verification_checks


def _build_evidence_tree(
    hypotheses: list[Any],
    signals: list[ProxySignal],
    accepted_case_id: str,
) -> dict[str, Any]:
    """Lightweight evidence tree for replay and UI."""
    accepted = next((h for h in hypotheses if h.case_id == accepted_case_id), None)
    rejected = [
        {
            "hypothesis": h.case_id,
            "reason": h.rejection_reason or "lower_rank_or_insufficient_signals",
        }
        for h in hypotheses
        if h.case_id != accepted_case_id
    ]
    return {
        "accepted_hypothesis": accepted_case_id,
        "accepted_because": list(accepted.supporting_signals) if accepted else [],
        "rejected_alternatives": rejected,
        "signal_count": len(signals),
    }


def _confidence_boundary(
    hypotheses: list[Any],
    verification_results: list[Any],
) -> ConfidenceBoundary:
    if not hypotheses:
        return ConfidenceBoundary(
            rank="low", rationale="No hypothesis matched input signals.", caps=["no_match"]
        )
    top = hypotheses[0]
    confirmed = [v for v in verification_results if v.status == "CONFIRMED"]
    rank = top.confidence_rank
    caps: list[str] = []
    if not confirmed:
        caps.append("verification_not_confirmed")
        if rank == "high":
            rank = "medium"
    if top.evidence_level != "proof":
        caps.append("not_proof_tier")
    return ConfidenceBoundary(
        rank=rank,
        rationale=f"Top hypothesis {top.case_id} at rank {top.confidence_rank}.",
        caps=caps,
    )


def _aggregate_evidence(
    signals: list[ProxySignal],
    hypotheses: list[Any],
    verification_results: list[Any],
) -> EvidenceAttributes:
    items: list[EvidenceItem] = []
    for sig in signals:
        items.append(
            EvidenceItem(
                label=sig.name,
                evidence_level="observed",
                detail=str(sig.value),
            ),
        )
    supports = []
    contradicts = []
    for hyp in hypotheses[:1]:
        supports.extend(hyp.supporting_signals)
    for hyp in hypotheses[1:]:
        contradicts.append(hyp.case_id)

    statuses = [v.status for v in verification_results]
    if "CONFIRMED" in statuses:
        vstatus = "CONFIRMED"
        strength = "strong"
    elif "REJECTED" in statuses and "CONFIRMED" not in statuses:
        vstatus = "REJECTED"
        strength = "weak"
    elif "INCONCLUSIVE" in statuses:
        vstatus = "INCONCLUSIVE"
        strength = "moderate"
    else:
        vstatus = "UNVERIFIED"
        strength = "weak"

    rank = hypotheses[0].confidence_rank if hypotheses else "low"
    if vstatus != "CONFIRMED" and rank == "high":
        rank = "medium"

    return EvidenceAttributes(
        evidence_items=items,
        supports=supports,
        contradicts=contradicts,
        verification_status=vstatus,
        confidence_boundary=rank,
        reproducibility="single_observation",
        conclusion_strength=strength,
    )


def run_proxy_reasoning(
    *,
    entity: ProxyEntity | None = None,
    signals: list[ProxySignal] | None = None,
    payload: dict[str, Any] | None = None,
    requested_action: str | None = None,
    explicit_confirmation: bool = False,
    proof_hints: dict[str, Any] | None = None,
    run_id: str | None = None,
) -> ProxyReasoningRun:
    """Execute the full proxy reasoning pipeline without host mutation.

    Args:
        entity: Pre-built ``ProxyEntity`` (optional if ``payload`` supplied).
        signals: Signal list aligned with ``entity`` (optional if ``payload`` supplied).
        payload: Collector-shaped dict from ``proxy_guard`` or CLI snapshots.
        requested_action: Action token evaluated by ``policy`` (e.g. ``diagnose``, ``restore_proxy``).
        explicit_confirmation: Operator confirmed destructive/previewed actions.
        proof_hints: Optional evidence attribute overrides for tests or replay.
        run_id: Optional stable id; generated when omitted.

    Returns:
        ``ProxyReasoningRun`` with hypotheses, verification, policy, and summary text.

    Raises:
        ValueError: When neither ``payload`` nor both ``entity`` and ``signals`` are provided.

    Side effects:
        None (audit append is caller responsibility).
    """
    from proxy_reasoning.builders import build_proxy_entity, signals_from_dict
    from proxy_reasoning.diagnosis_text import render_proxy_diagnosis

    if payload is not None:
        signals = signals_from_dict(payload)
        entity = build_proxy_entity(payload)

    if entity is None or signals is None:
        raise ValueError("run_proxy_reasoning requires entity+signals or payload")

    hypotheses = rank_hypotheses(signals)
    accepted = hypotheses[0].case_id if hypotheses else ""

    verification_results = run_verification_checks(entity, signals, proof_hints=proof_hints)
    confidence = _confidence_boundary(hypotheses, verification_results)
    policy = evaluate_proxy_policy(
        requested_action=requested_action,
        entity=entity,
        verification_results=verification_results,
        explicit_confirmation=explicit_confirmation,
    )

    evidence_attrs = _aggregate_evidence(signals, hypotheses, verification_results)
    entity = entity.model_copy(
        update={
            "evidence_attributes": evidence_attrs,
            "policy_attributes": policy,
        },
    )

    limitations: list[str] = []
    for hyp in hypotheses:
        limitations.extend(hyp.limitations)
    limitations.extend(entity.trust_risk_attributes.limitations)
    limitations.extend(entity.process_attribution_attributes.attribution_limitations)
    limitations = list(dict.fromkeys(limitations))

    run = ProxyReasoningRun(
        run_id=run_id or "",
        timestamp=utc_now_iso(),
        schema_version=SCHEMA_VERSION,
        engine_version=ENGINE_VERSION,
        entity=entity,
        signals=signals,
        events=[],  # events derivable from hypotheses; kept minimal for v1
        hypotheses=hypotheses,
        accepted_hypothesis=accepted,
        evidence_tree=_build_evidence_tree(hypotheses, signals, accepted),
        verification_results=verification_results,
        confidence_boundary=confidence,
        policy_decision=policy,
        limitations=limitations,
        requested_action=requested_action,
    )
    if not run.run_id:
        run = run.model_copy(update={"run_id": run.entity.entity_id})
    run = run.model_copy(update={"user_visible_summary": render_proxy_diagnosis(run)})
    return run

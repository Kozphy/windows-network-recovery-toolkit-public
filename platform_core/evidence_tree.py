"""Evidence tree helpers for endpoint reasoning runs."""

from __future__ import annotations

from platform_core.reasoning_models import (
    EndpointEvent,
    EvidenceNode,
    EvidenceTree,
    ProofResult,
    StateTransition,
)


def build_evidence_tree(
    *,
    run_id: str,
    accepted_hypothesis: str,
    events: list[EndpointEvent],
    transitions: list[StateTransition],
    rejected_alternatives: list[dict[str, str]],
    proof_result: ProofResult,
    limitations: list[str],
    recommended_next_steps: list[str],
) -> EvidenceTree:
    """Build an explainable evidence tree from deterministic reasoning artifacts.

    Args:
        run_id: Reasoning run identifier.
        accepted_hypothesis: Winning scenario ID.
        events: Events used by the reasoner.
        transitions: State transitions inferred from events.
        rejected_alternatives: Alternative hypotheses with rejection reasons.
        proof_result: Optional proof result.
        limitations: Known limitations and uncertainty.
        recommended_next_steps: Operator validation steps.

    Returns:
        Evidence tree that separates observed, inferred, proof, and rejected evidence.
    """
    observed_children = [
        EvidenceNode(
            label=event.event_type,
            evidence_level="observed",
            confidence=event.confidence,
            observation_ids=event.observation_ids,
            event_ids=[event.id],
            details=event.details,
            limitations=event.limitations,
            recommended_next_steps=event.recommended_next_steps,
        )
        for event in events
    ]
    inferred_children = [
        EvidenceNode(
            label=f"{transition.from_state}->{transition.to_state}",
            evidence_level="inferred",
            confidence=transition.confidence,
            event_ids=transition.event_ids,
            details={"rule_id": transition.rule_id},
            limitations=transition.limitations,
            recommended_next_steps=transition.recommended_next_steps,
        )
        for transition in transitions
    ]
    rejected_children = [
        EvidenceNode(
            label=item["hypothesis"],
            evidence_level="rejected",
            confidence=1.0,
            details={"reason": item["reason"]},
        )
        for item in rejected_alternatives
    ]
    proof_node = EvidenceNode(
        label=f"proof:{proof_result.status}",
        evidence_level="proof" if proof_result.status == "CONFIRMED" else "validated",
        confidence=proof_result.confidence,
        details={"checks_run": proof_result.checks_run, "evidence": proof_result.evidence},
        limitations=proof_result.limitations,
        recommended_next_steps=proof_result.recommended_next_steps,
    )
    root = EvidenceNode(
        label=accepted_hypothesis,
        evidence_level="inferred",
        confidence=max(
            [node.confidence for node in observed_children + inferred_children] or [0.0]
        ),
        children=[
            EvidenceNode(
                label="observed",
                evidence_level="observed",
                confidence=1.0,
                children=observed_children,
            ),
            EvidenceNode(
                label="state_transitions",
                evidence_level="inferred",
                confidence=1.0,
                children=inferred_children,
            ),
            proof_node,
            EvidenceNode(
                label="rejected_alternatives",
                evidence_level="rejected",
                confidence=1.0,
                children=rejected_children,
            ),
        ],
        limitations=limitations,
        recommended_next_steps=recommended_next_steps,
    )
    state_path = [transitions[0].from_state] if transitions else []
    state_path.extend(transition.to_state for transition in transitions)
    return EvidenceTree(
        run_id=run_id,
        accepted_hypothesis=accepted_hypothesis,
        state_path=state_path,
        accepted_because=[event.event_type for event in events],
        rejected_alternatives=rejected_alternatives,
        root=root,
        limitations=limitations,
        recommended_next_steps=recommended_next_steps,
    )

"""Evidence tree builder — mirrors endpoint reliability epistemic layering."""

from __future__ import annotations

from .models import EventEvidence, EvidenceTree, MarketEvent, SignalScore


def build_evidence_tree(event: MarketEvent, score: SignalScore) -> EvidenceTree:
    """Build evidence tree.
    
    Args:
        event: Evidence or domain record being processed.
        score: The score value supplied by the caller.
    
    Returns:
        The EvidenceTree result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    observation = (
        f"Calendar row: {event.title} ({event.category.value}) at {event.timestamp_utc} "
        f"affecting {', '.join(event.affected_assets) or 'unspecified assets'}."
    )
    interpretation = (
        f"Candidate interpretation: {event.direction_bias.value} bias with "
        f"{event.expected_volatility.value} expected volatility "
        f"(volatility_score={score.volatility_score}, direction_score={score.direction_score})."
    )

    supporting: list[EventEvidence] = []
    contradicting: list[EventEvidence] = []

    if event.source.strip():
        supporting.append(
            EventEvidence(
                node_id="src",
                label="Source attribution",
                kind="observation",
                detail=event.source,
                weight=0.6,
                supports_thesis=True,
            )
        )
    else:
        contradicting.append(
            EventEvidence(
                node_id="no_src",
                label="Missing source",
                kind="limitation",
                detail="Event has no source field — cannot corroborate headline.",
                weight=0.7,
                supports_thesis=False,
            )
        )

    for idx, driver in enumerate(score.main_drivers):
        supporting.append(
            EventEvidence(
                node_id=f"driver_{idx}",
                label="Scoring driver",
                kind="inference",
                detail=driver,
                weight=0.55,
                supports_thesis=True,
            )
        )

    for idx, risk in enumerate(score.risk_notes):
        contradicting.append(
            EventEvidence(
                node_id=f"risk_{idx}",
                label="Risk note",
                kind="counter_evidence",
                detail=risk,
                weight=0.5,
                supports_thesis=False,
            )
        )

    if event.direction_bias.value == "UNKNOWN":
        contradicting.append(
            EventEvidence(
                node_id="dir_unknown",
                label="Direction uncertainty",
                kind="limitation",
                detail="Direction bias is UNKNOWN — thesis direction is weak.",
                weight=0.45,
                supports_thesis=False,
            )
        )

    final_note = (
        "Correlation between calendar catalysts and realized price action is not causation. "
        f"Policy gate: {score.policy_status.value}. "
        "This output is a research signal only — not execution permission."
    )

    return EvidenceTree(
        event_id=event.event_id,
        observation=observation,
        candidate_interpretation=interpretation,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        confidence=score.confidence,
        final_research_note=final_note,
    )

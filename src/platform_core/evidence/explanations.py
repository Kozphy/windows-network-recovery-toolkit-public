"""Decision explanations — why hypotheses win and what proof is missing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.platform_core.evidence.conflicts import EvidenceConflict, detect_conflicts
from src.platform_core.evidence.tiers import EvidenceTier, tier_rank


@dataclass
class DecisionExplanation:
    """Represent the decision explanation type.

    Key fields:
        preferred_hypothesis: Structured value carried by this type.
        why_selected: Structured value carried by this type.
        missing_proof: Structured value carried by this type.
        unjustified_claims: Structured value carried by this type.
        conflicts: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    preferred_hypothesis: str
    why_selected: str
    missing_proof: list[str]
    unjustified_claims: list[str]
    conflicts: list[EvidenceConflict]


def build_explanation(
    *,
    incident_type: str,
    evidence_tier: EvidenceTier,
    confidence: float,
    signals: dict[str, Any],
    reasoning: str = "",
) -> DecisionExplanation:
    """Build explanation.

    Args:
        incident_type: incident type supplied by the caller.
        evidence_tier: evidence tier supplied by the caller.
        confidence: confidence supplied by the caller.
        signals: signals supplied by the caller.
        reasoning: reasoning supplied by the caller.

    Returns:
        The computed `DecisionExplanation` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    conflicts = detect_conflicts(signals)
    missing: list[str] = []
    unjustified: list[str] = []

    if tier_rank(evidence_tier) < tier_rank("PROVEN_REGISTRY_WRITER"):
        missing.append("Registry writer telemetry (e.g. Sysmon EID 13)")
    if tier_rank(evidence_tier) < tier_rank("PROVEN_NETWORK_IMPACT"):
        missing.append("Network path validation (direct vs proxy contrast)")
    if tier_rank(evidence_tier) < tier_rank("FINAL_CAUSATION"):
        missing.append("Process lineage + timestamp alignment for final causation")

    if tier_rank(evidence_tier) < tier_rank("FINAL_CAUSATION"):
        unjustified.append("Claiming certain root cause / writer identity")
    if tier_rank(evidence_tier) < tier_rank("CORRELATED"):
        unjustified.append("Attributing failure to a specific process")

    why = reasoning or f"Incident type {incident_type} ranked with ordinal confidence {confidence:.2f}."
    if conflicts:
        why += f" {len(conflicts)} signal conflict(s) limit stronger claims."

    return DecisionExplanation(
        preferred_hypothesis=incident_type,
        why_selected=why,
        missing_proof=missing,
        unjustified_claims=unjustified,
        conflicts=conflicts,
    )

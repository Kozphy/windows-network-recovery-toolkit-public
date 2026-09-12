"""Epistemic layer boundaries for event-state reasoning."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from platform_core.reasoning_models import EvidenceLevel, ProofStatus

ConclusionStrength = Literal["weak", "moderate", "strong"]


class EpistemicLayer(str, Enum):
    """Which epistemic bucket a claim belongs to."""

    OBSERVATION = "observation"
    INFERENCE = "inference"
    PROOF = "proof"
    POLICY = "policy"


_LAYER_TO_EVIDENCE: dict[EpistemicLayer, EvidenceLevel] = {
    EpistemicLayer.OBSERVATION: "observed",
    EpistemicLayer.INFERENCE: "inferred",
    EpistemicLayer.PROOF: "proof",
    EpistemicLayer.POLICY: "validated",
}


def evidence_level_for_layer(layer: EpistemicLayer) -> EvidenceLevel:
    """Map architecture layer to maximum evidence level for narrative copy."""
    return _LAYER_TO_EVIDENCE[layer]


def cap_conclusion_strength(
    *,
    desired: ConclusionStrength,
    evidence_level: EvidenceLevel,
    proof_status: ProofStatus = "NOT_RUN",
) -> ConclusionStrength:
    """Ensure conclusion strength does not exceed evidence strength.

    Rules:
        * ``observed`` / ``inferred`` cap at ``moderate`` unless proof is CONFIRMED.
        * ``rejected`` forces ``weak``.
        * CONFIRMED proof may support ``strong`` when desired is strong.
    """
    if evidence_level == "rejected":
        return "weak"
    if proof_status != "CONFIRMED":
        if desired == "strong":
            return "moderate"
        if evidence_level in ("observed", "inferred"):
            return "moderate" if desired == "strong" else desired
    if proof_status == "CONFIRMED" and evidence_level == "proof":
        return desired
    if desired == "strong":
        return "moderate"
    return desired

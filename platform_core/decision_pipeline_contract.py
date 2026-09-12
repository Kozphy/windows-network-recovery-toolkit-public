"""Canonical decision pipeline and evidence tier contract (assurance / policy alignment).

This module is the **single vocabulary** for:
- Pipeline stages: OBSERVE → … → AUDIT
- Evidence tiers: TIER_0 … TIER_3

It maps onto existing types in :mod:`platform_core.reasoning_models` (``EvidenceLevel``,
``ProofResult``) without changing their semantics. Callers can attach ``evidence_tier`` and
``pipeline_stage`` to JSONL audit rows as the platform converges on one schema.

Assurance note:
    Sysmon/EventLog registry writer telemetry is **attribution evidence** (correlation), not
    absolute proof of intent; product copy must keep that boundary (see ``limitations`` on
    registry writer facades under ``evidence/``).
"""

from __future__ import annotations

from typing import Literal

from platform_core.reasoning_models import EvidenceLevel, ProofResult

EvidenceTier = Literal[
    "TIER_0_RAW_OBSERVATION",
    "TIER_1_CORRELATED_SIGNAL",
    "TIER_2_CONTRAST_TESTED",
    "TIER_3_CAUSAL_PROOF",
]

PipelineStage = Literal[
    "OBSERVE",
    "CLASSIFY",
    "HYPOTHESIZE",
    "VERIFY",
    "POLICY_CHECK",
    "PREVIEW",
    "CONFIRM",
    "EXECUTE",
    "VALIDATE",
    "AUDIT",
]

ORDERED_PIPELINE_STAGES: tuple[PipelineStage, ...] = (
    "OBSERVE",
    "CLASSIFY",
    "HYPOTHESIZE",
    "VERIFY",
    "POLICY_CHECK",
    "PREVIEW",
    "CONFIRM",
    "EXECUTE",
    "VALIDATE",
    "AUDIT",
)

# Policy hint: minimum tier typically required before ALLOW for registry-touching remediation keys.
# Executors must still enforce typed confirmation and allowlists; this is guidance for UX/audit.
MIN_TIER_FOR_EXECUTE_AUTHORITY_PROXY_REGISTRY: EvidenceTier = "TIER_3_CAUSAL_PROOF"


def _max_observation_tier(level: EvidenceLevel) -> EvidenceTier:
    if level in ("observed",):
        return "TIER_0_RAW_OBSERVATION"
    if level in ("inferred", "validated", "rejected"):
        return "TIER_1_CORRELATED_SIGNAL"
    # legacy "proof" on an Observation without ProofResult — treat as correlated + tested claim
    return "TIER_2_CONTRAST_TESTED"


def resolve_evidence_tier(
    *,
    proof: ProofResult | None,
    observation_evidence_ceiling: EvidenceLevel = "observed",
) -> EvidenceTier:
    """Resolve the **dominant** evidence tier for a decision slice.

    Precedence (highest wins):
        1. Proof engine ``CONFIRMED`` → causal proof (narrow scope).
        2. Any proof checks executed (including ``REJECTED`` / ``INCONCLUSIVE``) → contrast-tested.
        3. Else ceiling from observations / state machine labels (ordinal).

    Args:
        proof: Optional :class:`~platform_core.reasoning_models.ProofResult`.
        observation_evidence_ceiling: Strongest ``EvidenceLevel`` seen on observations feeding
            the same run (caller computes max if needed).

    Returns:
        One of ``TIER_0_*`` … ``TIER_3_*``.
    """
    p = proof
    if p is not None:
        if p.status == "CONFIRMED":
            return "TIER_3_CAUSAL_PROOF"
        if p.checks_run and p.status != "NOT_RUN":
            return "TIER_2_CONTRAST_TESTED"
        if p.status != "NOT_RUN":
            # Defensive: status set without checks_run (should not happen)
            return "TIER_2_CONTRAST_TESTED"

    return _max_observation_tier(observation_evidence_ceiling)


def tier_ordinal(tier: EvidenceTier) -> int:
    """Return 0..3 for sorting and policy comparisons."""
    return {
        "TIER_0_RAW_OBSERVATION": 0,
        "TIER_1_CORRELATED_SIGNAL": 1,
        "TIER_2_CONTRAST_TESTED": 2,
        "TIER_3_CAUSAL_PROOF": 3,
    }[tier]


def policy_outcome_hint(
    *,
    tier: EvidenceTier,
    requires_registry_mutation: bool,
    explicit_confirmation: bool,
    risk_tier_high_or_critical: bool,
) -> Literal["ALLOW", "PREVIEW", "BLOCK"]:
    """Non-authoritative outcome hint for dashboards/tests.

    The **authoritative** policy remains in :mod:`platform_core.reasoning_engine` and
    :mod:`platform_core.policy` / route gates. This function encodes the assurance target:
    high/critical risk + registry mutation + missing causal proof → PREVIEW minimum.
    """
    if not requires_registry_mutation:
        return "PREVIEW"
    if risk_tier_high_or_critical and tier_ordinal(tier) < tier_ordinal("TIER_3_CAUSAL_PROOF"):
        return "PREVIEW"
    if tier_ordinal(tier) >= tier_ordinal("TIER_3_CAUSAL_PROOF") and explicit_confirmation:
        return "ALLOW"
    return "PREVIEW"

"""Formal proof-tier taxonomy for technology risk decisions.

Module responsibility:
    Defines the T0–T7 ``ProofTier`` ordered taxonomy and provides
    ``resolve_proof_tier`` to map a structured evidence fixture to the highest
    warranted tier.  T0–T5 preserve the existing evidence/governance ladder;
    T6 and T7 add controlled-validation and independent-verification assurance
    requirements.  ``map_proof_tier_to_evidence_tier`` translates T-levels to the
    canonical ``EvidenceTier`` vocabulary used by the rest of the platform.

System placement:
    Called by the ``/platform/proof-tier`` API route, the ``diagnose`` CLI
    command, and governance report generators.  Depends on fixture dicts produced
    by ``collect-evidence-bundle``; no live host probes are made.

Key invariants:
    - ``POSSIBLE_MITM_RISK`` and ``SUSPICIOUS_PROXY`` classifications are
      hard-capped at T2 (Runtime Corroboration) regardless of governance metadata,
      because stronger evidence does not convert a triage label into a verdict.
    - Proof strength (tier) is separate from execution authority; reaching T5 or
      higher does not automatically grant remediation rights.
    - Each ``ProofTierResult`` carries ``limitations[]`` asserting that tiers
      describe evidence strength, not malware confirmation or MITM proof.

Side effects:
    None.  All functions are pure; inputs are dicts, outputs are new objects.

Failure modes:
    Unknown ``ProofTier`` string values passed to ``map_proof_tier_to_evidence_tier``
    raise ``ValueError`` from ``ProofTier(str(tier))``.  ``resolve_proof_tier``
    falls back conservatively to T0 when no positive signals are present in the
    fixture.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ProofTier(StrEnum):
    """Represent the proof tier enum.

    Variants:
        T0_OBSERVATION_ONLY: Structured value carried by this enum.
        T1_LOCAL_CONFIG_EVIDENCE: Structured value carried by this enum.
        T2_RUNTIME_CORROBORATION: Structured value carried by this enum.
        T3_BEHAVIORAL_REPRODUCTION: Structured value carried by this enum.
        T4_OPERATOR_CONFIRMED: Structured value carried by this enum.
        T5_GOVERNANCE_PROOF: Structured value carried by this enum.
        T6_CONTROLLED_VALIDATION: Structured value carried by this enum.
        T7_INDEPENDENT_VERIFICATION: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    T0_OBSERVATION_ONLY = "T0_OBSERVATION_ONLY"
    T1_LOCAL_CONFIG_EVIDENCE = "T1_LOCAL_CONFIG_EVIDENCE"
    T2_RUNTIME_CORROBORATION = "T2_RUNTIME_CORROBORATION"
    T3_BEHAVIORAL_REPRODUCTION = "T3_BEHAVIORAL_REPRODUCTION"
    T4_OPERATOR_CONFIRMED = "T4_OPERATOR_CONFIRMED"
    T5_GOVERNANCE_PROOF = "T5_GOVERNANCE_PROOF"
    T6_CONTROLLED_VALIDATION = "T6_CONTROLLED_VALIDATION"
    T7_INDEPENDENT_VERIFICATION = "T7_INDEPENDENT_VERIFICATION"


_TIER_ORDER = [
    ProofTier.T0_OBSERVATION_ONLY,
    ProofTier.T1_LOCAL_CONFIG_EVIDENCE,
    ProofTier.T2_RUNTIME_CORROBORATION,
    ProofTier.T3_BEHAVIORAL_REPRODUCTION,
    ProofTier.T4_OPERATOR_CONFIRMED,
    ProofTier.T5_GOVERNANCE_PROOF,
    ProofTier.T6_CONTROLLED_VALIDATION,
    ProofTier.T7_INDEPENDENT_VERIFICATION,
]

_DEFAULT_LIMITATIONS = [
    "Proof tiers describe evidence strength — not malware, compromise, or MITM confirmation.",
    "Observation is not proof; correlation is not causation.",
    "Proof tier does not grant execution authority; policy and human approval remain separate.",
]


class ProofTierResult(BaseModel):
    """Represent the proof tier result type.

    Key fields:
        proof_tier: Structured value carried by this type.
        proof_tier_label: Structured value carried by this type.
        confidence_cap: Structured value carried by this type.
        limitations: Structured value carried by this type.
        rationale: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    proof_tier: ProofTier
    proof_tier_label: str
    confidence_cap: str = "ordinal_not_probability"
    limitations: list[str] = Field(default_factory=lambda: list(_DEFAULT_LIMITATIONS))
    rationale: str = ""


def _classification(fixture: dict[str, Any]) -> str:
    block = fixture.get("classification") or {}
    return str(block.get("primary_classification") or fixture.get("classification") or "").upper()


def _listener_found(fixture: dict[str, Any]) -> bool | None:
    owner = fixture.get("proxy_owner") or fixture.get("listener_info") or {}
    if "listener_found" in owner:
        return bool(owner.get("listener_found"))
    proxy_state = fixture.get("proxy_state") or fixture.get("proxy_status") or {}
    port = proxy_state.get("localhost_port")
    if port is not None and owner.get("process"):
        return True
    return None


def _proof_supported(fixture: dict[str, Any]) -> bool:
    proof = fixture.get("proof") or {}
    conclusion = proof.get("conclusion") or {}
    if conclusion.get("status") == "supported":
        return True
    for attempt in proof.get("proof_attempts") or []:
        if attempt.get("status") == "supported":
            return True
    return False


def _runtime_corroboration(fixture: dict[str, Any]) -> bool:
    proof = fixture.get("proof") or {}
    for attempt in proof.get("proof_attempts") or []:
        name = str(attempt.get("name", "")).lower()
        if name in {
            "localhost_listener_check",
            "wininet_winhttp_comparison",
            "direct_https_probe",
            "proxied_https_probe",
        }:
            if attempt.get("status") in ("supported", "failed"):
                return True
    return _proof_supported(fixture)


def _operator_confirmed(fixture: dict[str, Any]) -> bool:
    policy = fixture.get("policy_decision") or {}
    if policy.get("executed") and not policy.get("dry_run", True):
        return True
    if str(policy.get("confirmation_token_used") or "").strip():
        return True
    for row in fixture.get("audit_log_entries") or []:
        if row.get("confirmation_used") or row.get("executed"):
            return True
    return False


def _governance_proof(fixture: dict[str, Any]) -> bool:
    """T5: human-confirmed apply with verified audit chain reference."""
    if not _operator_confirmed(fixture):
        return False
    chain = fixture.get("audit_chain_verification") or {}
    if chain.get("verified") is True:
        return True
    for row in fixture.get("audit_log_entries") or []:
        if row.get("replay_certified") or row.get("chain_verified"):
            return True
    return bool(fixture.get("governance_proof"))


def _controlled_validation(fixture: dict[str, Any]) -> bool:
    """T6: controlled change/failure/rollback/recovery validation is reproducible."""
    validation = fixture.get("controlled_validation") or {}
    required = (
        validation.get("isolated_or_fixture_based") is True,
        validation.get("change_applied") is True,
        validation.get("failure_reproduced") is True,
        validation.get("rollback_applied") is True,
        validation.get("recovery_verified") is True,
        validation.get("repeatable") is True,
    )
    return _governance_proof(fixture) and all(required)


def _independent_verification(fixture: dict[str, Any]) -> bool:
    """T7: a separate verifier can validate integrity and reproduce the decision."""
    verification = fixture.get("independent_verification") or {}
    required = (
        verification.get("independent_verifier") is True,
        verification.get("evidence_bundle_verified") is True,
        verification.get("hash_chain_verified") is True,
        verification.get("deterministic_replay_verified") is True,
        verification.get("classification_reproduced") is True,
    )
    return _controlled_validation(fixture) and all(required)


def map_proof_tier_to_evidence_tier(tier: ProofTier | str) -> str:
    """Map T0–T7 proof tiers to canonical evidence-assurance vocabulary."""
    key = tier if isinstance(tier, ProofTier) else ProofTier(str(tier))
    mapping = {
        ProofTier.T0_OBSERVATION_ONLY: "OBSERVED_ONLY",
        ProofTier.T1_LOCAL_CONFIG_EVIDENCE: "OBSERVED_ONLY",
        ProofTier.T2_RUNTIME_CORROBORATION: "CORRELATED",
        ProofTier.T3_BEHAVIORAL_REPRODUCTION: "PROVEN_NETWORK_IMPACT",
        ProofTier.T4_OPERATOR_CONFIRMED: "PROVEN_REGISTRY_WRITER",
        ProofTier.T5_GOVERNANCE_PROOF: "GOVERNANCE_VERIFIED",
        ProofTier.T6_CONTROLLED_VALIDATION: "CONTROLLED_VALIDATION",
        ProofTier.T7_INDEPENDENT_VERIFICATION: "INDEPENDENTLY_VERIFIED",
    }
    return mapping.get(key, "OBSERVED_ONLY")


def resolve_proof_tier(fixture: dict[str, Any]) -> ProofTierResult:
    """Map fixture evidence to proof tier with conservative caps."""
    primary = _classification(fixture)
    listener = _listener_found(fixture)
    limitations = list(_DEFAULT_LIMITATIONS)
    rationale_parts: list[str] = []

    # Suspicious/MITM labels are deliberately capped before higher assurance
    # checks: stronger evidence does not convert a triage label into a verdict.
    if primary in ("POSSIBLE_MITM_RISK", "SUSPICIOUS_PROXY"):
        return ProofTierResult(
            proof_tier=ProofTier.T2_RUNTIME_CORROBORATION,
            proof_tier_label="Runtime Corroboration",
            rationale="Suspicious/MITM classifications remain triage-only regardless of governance metadata.",
            limitations=limitations
            + ["MITM or suspicious labels remain triage — not confirmed interception."],
        )

    if _independent_verification(fixture):
        return ProofTierResult(
            proof_tier=ProofTier.T7_INDEPENDENT_VERIFICATION,
            proof_tier_label="Independent verification",
            rationale="Independent verifier validated evidence integrity and deterministically reproduced the classification after controlled validation.",
            limitations=limitations
            + [
                "Independent verification increases assurance; it does not establish intent or remove human authorization requirements."
            ],
        )

    if _controlled_validation(fixture):
        return ProofTierResult(
            proof_tier=ProofTier.T6_CONTROLLED_VALIDATION,
            proof_tier_label="Controlled causal validation",
            rationale="Controlled change reproduced the failure and rollback restored service repeatedly with governance evidence preserved.",
            limitations=limitations
            + [
                "Controlled validation supports a bounded causal mechanism, not universal causation."
            ],
        )

    if _governance_proof(fixture):
        return ProofTierResult(
            proof_tier=ProofTier.T5_GOVERNANCE_PROOF,
            proof_tier_label="Governance-confirmed reproducible evidence chain",
            rationale="Human-confirmed action with audit chain verification.",
            limitations=limitations
            + ["Governance proof supports committee reporting — not formal audit opinion."],
        )

    if _operator_confirmed(fixture):
        return ProofTierResult(
            proof_tier=ProofTier.T4_OPERATOR_CONFIRMED,
            proof_tier_label="Operator-confirmed action recorded",
            rationale="Human confirmation or executed remediation with audit evidence.",
            limitations=limitations
            + ["Operator confirmation does not prove absence of compromise."],
        )

    tier = ProofTier.T0_OBSERVATION_ONLY
    rationale_parts.append("Baseline observation from available signals.")

    if primary or fixture.get("proxy_state") or fixture.get("proxy_status"):
        tier = ProofTier.T1_LOCAL_CONFIG_EVIDENCE
        rationale_parts.append("Local WinINET/WinHTTP configuration evidence present.")

    if _runtime_corroboration(fixture):
        tier = ProofTier.T2_RUNTIME_CORROBORATION
        rationale_parts.append(
            "Runtime path or stack contrast corroborates configuration hypothesis."
        )

    if primary == "DEAD_PROXY_CONFIG" and listener is False:
        tier = ProofTier.T1_LOCAL_CONFIG_EVIDENCE
        if _runtime_corroboration(fixture):
            tier = ProofTier.T2_RUNTIME_CORROBORATION
        else:
            rationale_parts.append(
                "Dead proxy without listener capped at T1–T2; no behavioral reproduction claimed."
            )
        limitations.append("Dead localhost proxy config does not imply malware or MITM.")

    if (
        _proof_supported(fixture)
        and tier == ProofTier.T2_RUNTIME_CORROBORATION
        and primary != "DEAD_PROXY_CONFIG"
    ):
        tier = ProofTier.T3_BEHAVIORAL_REPRODUCTION
        rationale_parts.append("Structured proof checks support reproducible failure pattern.")

    return ProofTierResult(
        proof_tier=tier,
        proof_tier_label=tier.value.replace("_", " ").title(),
        rationale=" ".join(rationale_parts),
        limitations=limitations,
    )

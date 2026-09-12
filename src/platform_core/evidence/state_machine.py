"""Formal evidence tier state machine with guarded, signal-driven transitions.

Module responsibility:
    ``EvidenceStateMachine`` tracks the current evidence tier for a single
    evidence-collection session and exposes two promotion paths: ``propose``
    (explicit tier + ``ProofInputs``) and ``apply_signals`` (raw signal dict,
    which computes ``ProofInputs`` internally and applies all feasible upgrades in
    ascending order).

System placement:
    Instantiated by the diagnosis pipeline when accumulating evidence from
    multiple collection steps (proxy-status → proxy-owner → Sysmon telemetry →
    path validation probes).  ``from_legacy_level`` supports initialisation from
    older tier vocabulary strings via ``normalize_tier``.

Key invariants:
    - Tier transitions are monotonically upward only; ``propose`` silently ignores
      same-tier transitions and rejects downgrades.
    - ``apply_signals`` always starts from ``"OBSERVED_ONLY"`` as the baseline
      candidate and applies upgrades in ascending tier order.
    - All promotion decisions are delegated to ``validate_tier_upgrade`` in
      ``guards.py``; the state machine itself contains no promotion logic.

Side effects:
    Mutates ``self.tier`` in-place when a transition is accepted.

Failure modes:
    An invalid tier string passed to ``from_legacy_level`` raises via
    ``normalize_tier``; callers should validate input before constructing.
"""

from __future__ import annotations

from typing import Any

from .guards import ProofInputs, proof_inputs_from_signals, validate_tier_upgrade
from .tiers import EvidenceTier, normalize_tier


class EvidenceStateMachine:
    """Stateful tier tracker with guarded transitions only."""

    def __init__(self, initial: EvidenceTier = "OBSERVED_ONLY") -> None:
        """Initialize the evidence state machine instance.

        Args:
            initial: initial supplied by the caller.

        Returns:
            None.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        self.tier: EvidenceTier = initial

    def propose(self, proposed: EvidenceTier, proof: ProofInputs) -> tuple[bool, str]:
        """Return propose.

        Args:
            proposed: proposed supplied by the caller.
            proof: proof supplied by the caller.

        Returns:
            The computed `tuple[bool, str]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        allowed, reason = validate_tier_upgrade(self.tier, proposed, proof)
        if allowed and proposed != self.tier:
            self.tier = proposed
        return allowed, reason

    def apply_signals(self, signals: dict[str, Any]) -> EvidenceTier:
        """Return apply signals.

        Args:
            signals: signals supplied by the caller.

        Returns:
            The computed `EvidenceTier` value.

        Side effects:
            Computes a signature artifact from the supplied payload.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        proof = proof_inputs_from_signals(signals)
        # Deterministic upgrade path from signals
        candidates: list[EvidenceTier] = ["OBSERVED_ONLY"]
        if proof.has_listener_correlation_only or any(
            k in signals for k in ("listener_on_proxy_port", "listener_process_name")
        ):
            candidates.append("CORRELATED")
        if proof.has_path_validation:
            candidates.append("PROVEN_NETWORK_IMPACT")
        if proof.has_registry_writer_telemetry:
            candidates.append("PROVEN_REGISTRY_WRITER")
        if proof.has_registry_writer_telemetry and proof.has_path_validation:
            if proof.has_process_lineage and proof.has_timestamp_alignment:
                candidates.append("FINAL_CAUSATION")

        for tier in candidates:
            self.propose(tier, proof)
        return self.tier

    @classmethod
    def from_legacy_level(cls, level: str) -> EvidenceStateMachine:
        """Return from legacy level.

        Args:
            level: level supplied by the caller.

        Returns:
            The computed `EvidenceStateMachine` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return cls(initial=normalize_tier(level))

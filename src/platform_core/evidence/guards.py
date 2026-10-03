"""Evidence tier upgrade guards — Observation != Proof.

Module responsibility:
    Enforces the project's evidence-tier promotion rules.  ``validate_tier_upgrade``
    returns ``(allowed, reason)`` for every proposed tier transition, using the
    ``ProofInputs`` dataclass to gate upgrades on verified signals (registry-writer
    telemetry, process lineage, timestamp alignment, path validation).
    ``can_unlock_destructive_remediation`` is the terminal gate: correlation-only
    evidence can never unlock destructive remediation regardless of tier label.

System placement:
    Used by ``EvidenceStateMachine`` (``state_machine.py``) for stateful tier
    tracking and by the policy engine to confirm that evidence supports the
    requested action.  ``proof_inputs_from_signals`` bridges raw signal dicts
    (e.g. from Sysmon or CLI flags) to the typed ``ProofInputs`` dataclass.

Key invariants:
    - ``FINAL_CAUSATION`` upgrade requires writer telemetry + process lineage +
      timestamp alignment + path validation; any missing signal rejects the
      upgrade.
    - ``manual_tier_override`` on ``ProofInputs`` is declared but must always be
      ``False`` from API/CLI paths; ``True`` for ``FINAL_CAUSATION`` is explicitly
      rejected by ``validate_tier_upgrade``.
    - Correlation-only evidence (``has_listener_correlation_only=True`` and
      ``has_registry_writer_telemetry=False``) always fails
      ``can_unlock_destructive_remediation``.

Side effects:
    None.  All functions are pure.

Failure modes:
    Unknown tier values passed to ``validate_tier_upgrade`` return
    ``(False, "Unknown tier transition to {proposed}")``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .tiers import EvidenceTier, tier_rank


@dataclass(frozen=True)
class ProofInputs:
    """Represent the proof inputs type.

    Key fields:
        has_registry_writer_telemetry: Structured value carried by this type.
        has_process_lineage: Structured value carried by this type.
        has_timestamp_alignment: Structured value carried by this type.
        has_path_validation: Structured value carried by this type.
        has_listener_correlation_only: Structured value carried by this type.
        has_replay_certification: Structured value carried by this type.
        manual_tier_override: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    has_registry_writer_telemetry: bool = False
    has_process_lineage: bool = False
    has_timestamp_alignment: bool = False
    has_path_validation: bool = False
    has_listener_correlation_only: bool = False
    has_replay_certification: bool = False
    manual_tier_override: bool = False  # must always be False from API/CLI


def validate_tier_upgrade(
    current: EvidenceTier,
    proposed: EvidenceTier,
    proof: ProofInputs,
) -> tuple[bool, str]:
    """Return (allowed, reason). Manual FINAL_CAUSATION override is always rejected."""
    if proof.manual_tier_override and proposed == "FINAL_CAUSATION":
        return False, "Manual FINAL_CAUSATION override forbidden"

    if tier_rank(proposed) <= tier_rank(current):
        return proposed == current, "No downgrade" if proposed != current else "unchanged"

    if proposed == "CORRELATED":
        return proof.has_listener_correlation_only or True, "correlation observed"

    if proposed == "PROVEN_NETWORK_IMPACT":
        return (
            proof.has_path_validation,
            "PROVEN_NETWORK_IMPACT requires network path validation proof",
        )

    if proposed == "PROVEN_REGISTRY_WRITER":
        return (
            proof.has_registry_writer_telemetry,
            "PROVEN_REGISTRY_WRITER requires writer telemetry",
        )

    if proposed == "FINAL_CAUSATION":
        ok = (
            proof.has_registry_writer_telemetry
            and proof.has_process_lineage
            and proof.has_timestamp_alignment
            and proof.has_path_validation
        )
        if not ok:
            return False, "FINAL_CAUSATION requires writer + lineage + alignment + path validation"
        return True, "guarded proof satisfied"

    return False, f"Unknown tier transition to {proposed}"


def can_unlock_destructive_remediation(tier: EvidenceTier, proof: ProofInputs) -> bool:
    """Correlation-only evidence must never unlock destructive remediation."""
    if proof.has_listener_correlation_only and not proof.has_registry_writer_telemetry:
        return False
    if tier_rank(tier) < tier_rank("FINAL_CAUSATION"):
        return False
    allowed, _ = validate_tier_upgrade("PROVEN_REGISTRY_WRITER", "FINAL_CAUSATION", proof)
    return allowed


def proof_inputs_from_signals(signals: dict[str, Any]) -> ProofInputs:
    """Return proof inputs from signals.

    Args:
        signals: signals supplied by the caller.

    Returns:
        The computed `ProofInputs` value.

    Side effects:
        Computes a signature artifact from the supplied payload.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """

    def truthy(v: Any) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.strip().lower() in {"1", "true", "yes", "on"}
        return bool(v)

    return ProofInputs(
        has_registry_writer_telemetry=truthy(
            signals.get("sysmon_event_13") or signals.get("registry_writer_observed")
        ),
        has_process_lineage=truthy(signals.get("writer_process") or signals.get("process_lineage")),
        has_timestamp_alignment=truthy(signals.get("timestamp_alignment")),
        has_path_validation=truthy(
            signals.get("proxy_bypass_succeeded")
            or signals.get("direct_path_success")
            or signals.get("path_validated")
        ),
        has_listener_correlation_only=truthy(
            signals.get("listener_on_proxy_port") or signals.get("listener_correlation")
        )
        and not truthy(signals.get("sysmon_event_13")),
        has_replay_certification=truthy(signals.get("replay_certified")),
        manual_tier_override=truthy(signals.get("force_final_causation")),
    )

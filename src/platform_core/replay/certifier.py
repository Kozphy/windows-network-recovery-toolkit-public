"""Certified deterministic replay."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.platform_core.evidence.guards import (
    can_unlock_destructive_remediation,
    proof_inputs_from_signals,
)
from src.platform_core.pipeline import PipelineResult, run_decision_pipeline
from src.platform_core.replay.hash import stable_hash


@dataclass
class CertificationResult:
    """Represent the certification result type.

    Key fields:
        certified: Structured value carried by this type.
        certification_hash: Structured value carried by this type.
        tier: Structured value carried by this type.
        policy_outcome: Structured value carried by this type.
        destructive_unlocked: Structured value carried by this type.
        errors: Structured value carried by this type.

    Side effects:
        None.
    """
    certified: bool
    certification_hash: str
    tier: str
    policy_outcome: str
    destructive_unlocked: bool
    errors: list[str]


def certify_case(
    *,
    signals: dict[str, Any] | None = None,
    jsonl_path: Path | str | None = None,
) -> CertificationResult:
    """Certify case.

    Args:
        signals: signals supplied by the caller.
        jsonl_path: jsonl path supplied by the caller.

    Returns:
        The computed `CertificationResult` value.

    Side effects:
        None.
    """
    errors: list[str] = []
    r1 = run_decision_pipeline(signals=signals, jsonl_path=jsonl_path)
    r2 = run_decision_pipeline(signals=signals, jsonl_path=jsonl_path)

    h1 = stable_hash(_snapshot(r1))
    h2 = stable_hash(_snapshot(r2))
    if h1 != h2:
        errors.append("non-deterministic replay hash")

    proof = proof_inputs_from_signals(signals or _signals_from_result(r1))
    destructive_ok = can_unlock_destructive_remediation(r1.bundle.tier, proof)
    if destructive_ok and r1.bundle.tier != "FINAL_CAUSATION":
        errors.append("destructive unlocked without FINAL_CAUSATION")

  # Correlation-only must not unlock destructive
    corr_only = proof.has_listener_correlation_only and not proof.has_registry_writer_telemetry
    if corr_only and destructive_ok:
        errors.append("correlation-only unlocked destructive remediation")

    policy_outcome = r1.policy.outcome
    certified = len(errors) == 0
    return CertificationResult(
        certified=certified,
        certification_hash=h1,
        tier=r1.bundle.tier,
        policy_outcome=policy_outcome,
        destructive_unlocked=destructive_ok,
        errors=errors,
    )


def _snapshot(result: PipelineResult) -> dict[str, Any]:
    """Semantic outputs only — excludes ephemeral UUIDs and audit chain noise."""
    return {
        "tier": result.bundle.tier,
        "incident_type": result.decision.incident_type,
        "confidence": result.decision.confidence,
        "recommended_action": result.decision.recommended_action,
        "policy_outcome": result.policy.outcome,
        "policy_allowed": result.policy.allowed,
        "requires_approval": result.policy.requires_approval,
    }


def _signals_from_result(result: PipelineResult) -> dict[str, Any]:
    return {item.signal: item.observed_value for item in result.bundle.items}

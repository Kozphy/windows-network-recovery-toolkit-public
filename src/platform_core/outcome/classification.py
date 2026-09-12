"""Outcome classification — deterministic, not autonomous AI."""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class OutcomeClassification(StrEnum):
    """Represent the outcome classification enum.

    Variants:
        SUCCESSFUL_REMEDIATION: Structured value carried by this enum.
        PARTIAL_RECOVERY: Structured value carried by this enum.
        NO_IMPACT: Structured value carried by this enum.
        REGRESSION: Structured value carried by this enum.
        INCONCLUSIVE: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    SUCCESSFUL_REMEDIATION = "SUCCESSFUL_REMEDIATION"
    PARTIAL_RECOVERY = "PARTIAL_RECOVERY"
    NO_IMPACT = "NO_IMPACT"
    REGRESSION = "REGRESSION"
    INCONCLUSIVE = "INCONCLUSIVE"


def classify_outcome(
    *,
    was_successful: bool | None,
    was_false_positive: bool | None = None,
    was_blocked_by_policy: bool = False,
    rollback_required: bool = False,
    notes: str = "",
) -> OutcomeClassification:
    """Classify outcome.

    Args:
        was_successful: was successful supplied by the caller.
        was_false_positive: was false positive supplied by the caller.
        was_blocked_by_policy: was blocked by policy supplied by the caller.
        rollback_required: rollback required supplied by the caller.
        notes: notes supplied by the caller.

    Returns:
        The computed `OutcomeClassification` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    if was_blocked_by_policy:
        return OutcomeClassification.NO_IMPACT
    if rollback_required or was_false_positive:
        return OutcomeClassification.REGRESSION
    if was_successful is True:
        return OutcomeClassification.SUCCESSFUL_REMEDIATION
    if was_successful is False:
        return OutcomeClassification.PARTIAL_RECOVERY
    if "partial" in notes.lower():
        return OutcomeClassification.PARTIAL_RECOVERY
    return OutcomeClassification.INCONCLUSIVE


def outcome_record_fields(
    *,
    decision_id: str,
    evidence_tier: str,
    policy_gate: str,
    remediation_preview: dict[str, Any] | None,
    actual_result: str,
    classification: OutcomeClassification,
    rollback_required: bool,
) -> dict[str, Any]:
    """Return outcome record fields.

    Args:
        decision_id: decision id supplied by the caller.
        evidence_tier: evidence tier supplied by the caller.
        policy_gate: policy gate supplied by the caller.
        remediation_preview: remediation preview supplied by the caller.
        actual_result: actual result supplied by the caller.
        classification: classification supplied by the caller.
        rollback_required: rollback required supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        Records data in the configured store or telemetry sink.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return {
        "decision_id": decision_id,
        "evidence_tier": evidence_tier,
        "policy_gate": policy_gate,
        "remediation_preview": remediation_preview or {},
        "actual_result": actual_result,
        "classification": classification.value,
        "rollback_required": rollback_required,
    }

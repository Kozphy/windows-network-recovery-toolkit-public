"""Coordinate policy + stakeholder + timing into a DecisionEnvelope.

Module responsibility:
    Orchestrates three sub-evaluations — ``resolve_stakeholders``, ``evaluate_timing``,
    and ``normalize_policy_outcome`` — into a single ``DecisionEnvelope`` artifact.
    ``derive_coordination_status`` implements deterministic precedence rules: policy blocks
    always dominate, followed by timing expiry/SLA, then stakeholder gaps.
    ``build_decision_envelope`` writes an audit record when ``write_audit=True`` and
    attaches the result to the governance envelope used by downstream reporting.

Typical usage:
    envelope = build_decision_envelope(case_id=..., policy_decision="PREVIEW_ONLY", ...)

Limitations:
    - Policy outcome normalization relies on ``CanonicalPolicyGate``; unrecognised strings
      fall through to string-upper comparison and may not match all caller conventions.
    - Stakeholder and timing configs default to module-level defaults when omitted; callers
      should supply configs explicitly for production fixtures.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.platform_core.audit.writer import append_audit
from src.platform_core.decision_context.models import (
    SCHEMA_DECISION_CONTEXT,
    CoordinationStatus,
    DecisionEnvelope,
)
from src.platform_core.policy.outcome_normalizer import (
    CanonicalPolicyGate,
    normalize_policy_outcome,
)
from src.platform_core.stakeholder.models import StakeholderReasonCode
from src.platform_core.stakeholder.resolver import resolve_stakeholders
from src.platform_core.timing.evaluator import evaluate_timing
from src.platform_core.timing.models import TimingDecision

_BLOCKING_GATES = frozenset(
    {
        CanonicalPolicyGate.BLOCK,
    }
)


def _policy_blocks_execution(policy_decision: str, policy_allowed: bool) -> bool:
    gate = normalize_policy_outcome(policy_decision)
    if gate in _BLOCKING_GATES:
        return True
    if str(policy_decision).upper() in {
        "BLOCK",
        "BLOCK_DESTRUCTIVE",
        "BLOCK_LOW_CONFIDENCE",
        "BLOCK_UNSAFE_ACTION",
        "BLOCK_AUTOMATION",
    }:
        return True
    return False


def derive_coordination_status(
    *,
    policy_decision: str,
    policy_allowed: bool,
    policy_requires_approval: bool,
    stakeholder_unresolved: tuple[str, ...],
    stakeholder_reasons: tuple[Any, ...],
    timing_decision: TimingDecision | None,
) -> CoordinationStatus:
    """Deterministic coordination rules (policy always dominates blocks)."""
    if _policy_blocks_execution(policy_decision, policy_allowed):
        # Urgent escalation may still be recorded separately; coordination stays blocked.
        if timing_decision == TimingDecision.ESCALATE_NOW:
            return CoordinationStatus.ESCALATE_NOW
        return CoordinationStatus.BLOCKED_BY_POLICY

    if timing_decision == TimingDecision.EVIDENCE_EXPIRED:
        return CoordinationStatus.EXPIRED
    if timing_decision == TimingDecision.SLA_OVERDUE:
        # overdue is coordination-critical but does not execute
        if (
            StakeholderReasonCode.OWNER_UNRESOLVED in stakeholder_reasons
            or "asset_owner" in stakeholder_unresolved
        ):
            return CoordinationStatus.NEEDS_OWNER
        if policy_requires_approval:
            return CoordinationStatus.NEEDS_APPROVAL
        return CoordinationStatus.ESCALATE_NOW
    if timing_decision == TimingDecision.BLOCKED_BY_CHANGE_FREEZE:
        return CoordinationStatus.BLOCKED_BY_CHANGE_FREEZE
    if timing_decision == TimingDecision.DEFERRED_TO_WINDOW:
        return CoordinationStatus.DEFERRED_TO_WINDOW
    if timing_decision == TimingDecision.MONITOR_UNTIL:
        return CoordinationStatus.MONITOR_UNTIL
    if timing_decision == TimingDecision.ESCALATE_NOW:
        return CoordinationStatus.ESCALATE_NOW

    if (
        "asset_owner" in stakeholder_unresolved
        or StakeholderReasonCode.OWNER_UNRESOLVED in stakeholder_reasons
    ):
        return CoordinationStatus.NEEDS_OWNER

    if policy_requires_approval or StakeholderReasonCode.APPROVER_REQUIRED in stakeholder_reasons:
        if "approver" in stakeholder_unresolved or "execution_authority" in stakeholder_unresolved:
            return CoordinationStatus.NEEDS_APPROVAL
        return CoordinationStatus.NEEDS_APPROVAL

    return CoordinationStatus.READY


def build_decision_envelope(
    *,
    case_id: str,
    decision_id: str = "",
    evidence_refs: list[str] | None = None,
    ranked_hypotheses: list[dict[str, Any]] | None = None,
    proof_result: dict[str, Any] | None = None,
    policy_decision: str = "PREVIEW_ONLY",
    policy_allowed: bool = False,
    policy_requires_approval: bool = True,
    classification: str = "",
    proof_status: str = "",
    detected_at_utc: str | None = None,
    timezone_name: str | None = None,
    stakeholder_config: dict[str, Any] | None = None,
    timing_config: dict[str, Any] | None = None,
    remediation_preview: dict[str, Any] | None = None,
    control_ids: list[str] | None = None,
    evidence_summary: dict[str, Any] | None = None,
    write_audit: bool = True,
    actor: str = "platform",
) -> DecisionEnvelope:
    """Orchestrate stakeholder + timing around an existing policy decision."""
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    detected = detected_at_utc or now
    proof_result = proof_result or {}
    classification = classification or str(proof_result.get("classification") or "")

    stakeholder = resolve_stakeholders(
        case_id=case_id,
        classification=classification,
        evidence_summary=evidence_summary,
        proof_status=proof_status or str(proof_result.get("proof_tier") or ""),
        policy_outcome=policy_decision,
        policy_requires_approval=policy_requires_approval,
        control_ids=control_ids,
        config=stakeholder_config,
    )
    timing = evaluate_timing(
        case_id=case_id,
        detected_at_utc=detected,
        evaluated_at_utc=now,
        timezone_name=timezone_name,
        classification=classification,
        policy_outcome=policy_decision,
        config=timing_config,
    )
    coordination = derive_coordination_status(
        policy_decision=policy_decision,
        policy_allowed=policy_allowed,
        policy_requires_approval=policy_requires_approval,
        stakeholder_unresolved=stakeholder.unresolved_fields,
        stakeholder_reasons=stakeholder.reason_codes,
        timing_decision=timing.decision,
    )

    audit_meta: dict[str, Any] = {
        "schema_version": SCHEMA_DECISION_CONTEXT,
        "policy_decision": policy_decision,
        "coordination_status": coordination.value,
        "stakeholder_fingerprint": stakeholder.inputs_fingerprint,
        "timing_fingerprint": timing.inputs_fingerprint,
    }
    if write_audit:
        for action_type, payload in (
            (
                "stakeholder_resolved",
                {
                    "reason_codes": [r.value for r in stakeholder.reason_codes],
                    "unresolved_fields": list(stakeholder.unresolved_fields),
                    "resolution_confidence": stakeholder.resolution_confidence,
                    "inputs_fingerprint": stakeholder.inputs_fingerprint,
                },
            ),
            (
                "timing_evaluated",
                {
                    "decision": timing.decision.value,
                    "urgency": timing.urgency.value,
                    "sla_due_utc": timing.sla_due_utc,
                    "evidence_expires_utc": timing.evidence_expires_utc,
                    "reason_codes": [r.value for r in timing.reason_codes],
                    "timezone": timing.timezone,
                    "inputs_fingerprint": timing.inputs_fingerprint,
                },
            ),
            (
                "coordination_status_set",
                {
                    "policy_decision": policy_decision,
                    "coordination_status": coordination.value,
                    "execution_authority_present": stakeholder.execution_authority is not None,
                },
            ),
            (
                "decision_context_built",
                {"schema_version": SCHEMA_DECISION_CONTEXT, "case_id": case_id},
            ),
        ):
            rec = append_audit(
                action_type,  # type: ignore[arg-type]
                trace_id=case_id,
                decision_id=decision_id or case_id,
                incident_id=case_id,
                actor=actor,
                payload=payload,
            )
            audit_meta.setdefault("audit_ids", []).append(rec.audit_id)

    preview = remediation_preview or {
        "dry_run": True,
        "preview_only": True,
        "message": "Remediation remains preview-only; coordination does not authorize apply.",
        "coordination_status": coordination.value,
        "policy_decision": policy_decision,
    }

    return DecisionEnvelope(
        case_id=case_id,
        decision_id=decision_id or case_id,
        evidence_refs=tuple(evidence_refs or []),
        ranked_hypotheses=tuple(ranked_hypotheses or []),
        proof_result=proof_result,
        policy_decision=policy_decision,
        policy_allowed=policy_allowed,
        policy_requires_approval=policy_requires_approval,
        stakeholder=stakeholder,
        timing=timing,
        coordination_status=coordination,
        remediation_preview=preview,
        audit_metadata=audit_meta,
    )

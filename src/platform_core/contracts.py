"""Canonical typed contracts for the decision pipeline."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.platform_core import AUDIT_SCHEMA_VERSION, SCHEMA_VERSION

EvidenceTierName = Literal[
    "OBSERVED_ONLY",
    "CORRELATED",
    "PROVEN_REGISTRY_WRITER",
    "PROVEN_NETWORK_IMPACT",
    "FINAL_CAUSATION",
]

PolicyOutcomeName = Literal[
    "ALLOW",
    "PREVIEW_ONLY",
    "REQUIRE_HUMAN_APPROVAL",
    "BLOCK",
    "ROLLBACK_REQUIRED",
]

AuditActionType = Literal[
    "event_received",
    "evidence_attached",
    "hypothesis_created",
    "decision_created",
    "policy_evaluated",
    "remediation_previewed",
    "human_approval_requested",
    "human_approval_granted",
    "action_executed",
    "validation_completed",
    "rollback_completed",
    "outcome_recorded",
    "replay_certified",
    "stakeholder_resolved",
    "timing_evaluated",
    "coordination_status_set",
    "decision_context_built",
]


class NormalizedEvent(BaseModel):
    """Represent the normalized event type.

    Key fields:
        event_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        source: Structured value carried by this type.
        category: Structured value carried by this type.
        title: Structured value carried by this type.
        trace_id: Structured value carried by this type.
        severity: Structured value carried by this type.

    Side effects:
        None.
    """

    event_id: str
    schema_version: str = SCHEMA_VERSION
    timestamp_utc: str
    source: str
    category: str
    title: str
    trace_id: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    observations: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    """Represent the evidence item type.

    Key fields:
        evidence_id: Structured value carried by this type.
        event_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        source: Structured value carried by this type.
        signal: Structured value carried by this type.
        observed_value: Structured value carried by this type.
        tier: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    evidence_id: str
    event_id: str
    schema_version: str = SCHEMA_VERSION
    timestamp_utc: str
    source: str
    signal: str
    observed_value: str = ""
    tier: EvidenceTierName = "OBSERVED_ONLY"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class EvidenceBundle(BaseModel):
    """Represent the evidence bundle type.

    Key fields:
        bundle_id: Structured value carried by this type.
        incident_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        created_at: Structured value carried by this type.
        host_id: Structured value carried by this type.
        tier: Structured value carried by this type.
        items: Structured value carried by this type.
        summary: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    bundle_id: str
    incident_id: str
    schema_version: str = SCHEMA_VERSION
    created_at: str
    host_id: str = "local"
    tier: EvidenceTierName = "OBSERVED_ONLY"
    items: list[EvidenceItem] = Field(default_factory=list)
    summary: str = ""
    tags: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    """Represent the hypothesis type.

    Key fields:
        hypothesis_id: Structured value carried by this type.
        event_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        title: Structured value carried by this type.
        explanation: Structured value carried by this type.
        confidence: Structured value carried by this type.
        supporting_evidence_ids: Structured value carried by this type.
        incident_type: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    hypothesis_id: str
    event_id: str
    schema_version: str = SCHEMA_VERSION
    title: str
    explanation: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    incident_type: str = ""


class Decision(BaseModel):
    """Represent the decision type.

    Key fields:
        decision_id: Structured value carried by this type.
        incident_id: Structured value carried by this type.
        trace_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        incident_type: Structured value carried by this type.
        recommended_action: Structured value carried by this type.
        confidence: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    decision_id: str
    incident_id: str
    trace_id: str = ""
    schema_version: str = SCHEMA_VERSION
    timestamp_utc: str
    incident_type: str
    recommended_action: str
    confidence: float = Field(ge=0.0, le=1.0)
    risk_level: Literal["low", "medium", "high", "critical"] = "medium"
    evidence_tier: EvidenceTierName = "OBSERVED_ONLY"
    evidence_refs: list[str] = Field(default_factory=list)
    reasoning: str = ""
    requires_human_review: bool = False


class PolicyEvaluation(BaseModel):
    """Represent the policy evaluation type.

    Key fields:
        evaluation_id: Structured value carried by this type.
        decision_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        requested_action: Structured value carried by this type.
        evidence_tier: Structured value carried by this type.
        outcome: Structured value carried by this type.
        allowed: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    evaluation_id: str
    decision_id: str
    schema_version: str = SCHEMA_VERSION
    timestamp_utc: str
    requested_action: str
    evidence_tier: EvidenceTierName
    outcome: PolicyOutcomeName
    allowed: bool
    requires_approval: bool
    requires_rollback_plan: bool
    blocked_reasons: list[str] = Field(default_factory=list)
    rationale: str = ""


class PolicyOutcome(BaseModel):
    """Represent the policy outcome type.

    Key fields:
        outcome: Structured value carried by this type.
        dry_run: Structured value carried by this type.
        allowed_actions: Structured value carried by this type.
        blocked_actions: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    outcome: PolicyOutcomeName
    dry_run: bool = True
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)


class OperatorAction(BaseModel):
    """Represent the operator action type.

    Key fields:
        action_id: Structured value carried by this type.
        decision_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        action_type: Structured value carried by this type.
        approval_token: Structured value carried by this type.
        dry_run: Structured value carried by this type.
        operator_id: Structured value carried by this type.

    Side effects:
        None.
    """

    action_id: str
    decision_id: str
    schema_version: str = SCHEMA_VERSION
    timestamp_utc: str
    action_type: str
    approval_token: str = ""
    dry_run: bool = True
    operator_id: str = "local"


class IncidentOutcome(BaseModel):
    """Represent the incident outcome type.

    Key fields:
        outcome_id: Structured value carried by this type.
        decision_id: Structured value carried by this type.
        incident_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        created_at: Structured value carried by this type.
        recommended_action: Structured value carried by this type.
        policy_outcome: Structured value carried by this type.
        operator_action: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    outcome_id: str
    decision_id: str
    incident_id: str
    schema_version: str = SCHEMA_VERSION
    created_at: str
    recommended_action: str
    policy_outcome: str
    operator_action: str = ""
    actual_outcome: str = ""
    time_to_resolution_seconds: float | None = None
    was_successful: bool | None = None
    was_false_positive: bool | None = None
    was_blocked_by_policy: bool = False
    notes: str = ""


class AuditRecord(BaseModel):
    """Represent the audit record type.

    Key fields:
        audit_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        timestamp_utc: Structured value carried by this type.
        action_type: Structured value carried by this type.
        trace_id: Structured value carried by this type.
        decision_id: Structured value carried by this type.
        incident_id: Structured value carried by this type.
        actor: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    audit_id: str
    schema_version: str = AUDIT_SCHEMA_VERSION
    timestamp_utc: str
    action_type: AuditActionType
    trace_id: str = ""
    decision_id: str = ""
    incident_id: str = ""
    actor: str = "platform"
    payload: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = ""
    current_hash: str = ""
    signature_status: Literal["unsigned", "hash_chained", "signed"] = "hash_chained"
    # Domain event envelope fields (wnrt.domain_event.v1) — optional for legacy rows.
    event_id: str = ""
    event_type: str = ""
    source: str = ""
    tenant_id: str = ""
    correlation_id: str = ""
    custody: dict[str, Any] = Field(default_factory=dict)


class ReplayCase(BaseModel):
    """Represent the replay case type.

    Key fields:
        case_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        fixture_path: Structured value carried by this type.
        signals: Structured value carried by this type.
        expected_tier: Structured value carried by this type.
        expected_policy: Structured value carried by this type.
        certification_hash: Structured value carried by this type.

    Side effects:
        None.
    """

    case_id: str
    schema_version: str = SCHEMA_VERSION
    fixture_path: str = ""
    signals: dict[str, Any] = Field(default_factory=dict)
    expected_tier: EvidenceTierName | None = None
    expected_policy: PolicyOutcomeName | None = None
    certification_hash: str = ""


class LearningRecord(BaseModel):
    """Represent the learning record type.

    Key fields:
        record_id: Structured value carried by this type.
        decision_id: Structured value carried by this type.
        schema_version: Structured value carried by this type.
        created_at: Structured value carried by this type.
        feedback_type: Structured value carried by this type.
        metrics_snapshot: Structured value carried by this type.

    Side effects:
        None.
    """

    record_id: str
    decision_id: str
    schema_version: str = SCHEMA_VERSION
    created_at: str
    feedback_type: str
    metrics_snapshot: dict[str, Any] = Field(default_factory=dict)


class DestructiveAction(StrEnum):
    """Represent the destructive action enum.

    Variants:
        REGISTRY_MODIFICATION: Structured value carried by this enum.
        KILL_PROCESS: Structured value carried by this enum.
        DISABLE_PROXY: Structured value carried by this enum.
        FIREWALL_RESET: Structured value carried by this enum.
        ADAPTER_DISABLE: Structured value carried by this enum.
        DELETE_FILES: Structured value carried by this enum.
        SYSTEM_NETWORK_CHANGE: Structured value carried by this enum.

    Side effects:
        None.
    """

    REGISTRY_MODIFICATION = "registry_modification"
    KILL_PROCESS = "kill_process"
    DISABLE_PROXY = "disable_proxy"
    FIREWALL_RESET = "firewall_reset"
    ADAPTER_DISABLE = "adapter_disable"
    DELETE_FILES = "delete_files"
    SYSTEM_NETWORK_CHANGE = "system_network_change"

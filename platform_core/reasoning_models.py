"""Typed event/state reasoning models for endpoint reliability runs.

These models are intentionally deterministic and local-first. Confidence is an ordinal ranking
score, not a calibrated probability. The models separate observations, events, state transitions,
evidence, proof, policy, audit metadata, and human-readable recommendations.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field

from platform_core.models import utc_now_iso

ConfidenceScore = float
EvidenceLevel = Literal["observed", "inferred", "validated", "proof", "rejected"]
EventSeverity = Literal["info", "low", "medium", "high", "critical"]
EventStatus = Literal["observed", "inferred", "rejected"]
ProofStatus = Literal["NOT_RUN", "CONFIRMED", "REJECTED", "INCONCLUSIVE"]
PolicyOutcome = Literal["ALLOW", "PREVIEW", "BLOCK"]
ImpactSeverity = Literal["low", "medium", "high", "critical"]
ImpactScope = Literal[
    "browser_only", "dev_tools", "browser_and_dev_tools", "system_wide", "multi_endpoint"
]
ImpactDuration = Literal["short", "medium", "long", "unknown"]


def new_id(prefix: str) -> str:
    """Create a short typed identifier.

    Args:
        prefix: Stable prefix such as ``obs`` or ``run``.

    Returns:
        String identifier with a UUID suffix.
    """
    return f"{prefix}_{uuid.uuid4().hex}"


class AuditMetadata(BaseModel):
    """Common audit context attached to reasoning artifacts."""

    schema_version: str = "reasoning.v1"
    engine_version: str = "2026.05"
    replayable: bool = True
    source_run_id: str | None = None
    tags: list[str] = Field(default_factory=list)


class Observation(BaseModel):
    """Raw or normalized endpoint fact from a collector, fixture, or replay."""

    id: str = Field(default_factory=lambda: new_id("obs"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "unknown"
    signal_name: str
    value: Any
    normalized_value: Any | None = None
    confidence: ConfidenceScore = Field(default=1.0, ge=0.0, le=1.0)
    evidence_level: EvidenceLevel = "observed"
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class EndpointEvent(BaseModel):
    """Normalized event derived from one or more observations."""

    id: str = Field(default_factory=lambda: new_id("evt"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "reasoning_engine"
    event_type: str
    category: str = ""
    severity: EventSeverity = "info"
    status: EventStatus = "observed"
    confidence: ConfidenceScore = Field(default=1.0, ge=0.0, le=1.0)
    observation_ids: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_id(self) -> str:
        """Stable external identifier (alias of ``id`` for audit/API contracts)."""
        return self.id


class EndpointState(BaseModel):
    """Named endpoint/network state at a point in the reasoning path."""

    id: str
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "scenario_registry"
    label: str
    confidence: ConfidenceScore = Field(default=0.0, ge=0.0, le=1.0)
    evidence_level: EvidenceLevel = "inferred"
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class StateTransition(BaseModel):
    """Transition between two endpoint states caused by observed events."""

    id: str = Field(default_factory=lambda: new_id("transition"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "reasoning_engine"
    from_state: str
    to_state: str
    event_ids: list[str] = Field(default_factory=list)
    rule_id: str = ""
    confidence: ConfidenceScore = Field(default=0.0, ge=0.0, le=1.0)
    evidence_level: EvidenceLevel = "inferred"
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class FailureScenario(BaseModel):
    """Reusable failure chain with states, events, rules, and alternatives."""

    id: str
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "failure_scenario_registry"
    name: str
    description: str
    states: list[str]
    events: list[str]
    rules: list[dict[str, Any]] = Field(default_factory=list)
    alternative_hypotheses: list[str] = Field(default_factory=list)
    confidence: ConfidenceScore = Field(default=0.0, ge=0.0, le=1.0)
    evidence_level: EvidenceLevel = "inferred"
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class EvidenceNode(BaseModel):
    """One node in the diagnostic evidence tree."""

    id: str = Field(default_factory=lambda: new_id("evidence"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "reasoning_engine"
    label: str
    evidence_level: EvidenceLevel
    confidence: ConfidenceScore = Field(default=0.0, ge=0.0, le=1.0)
    observation_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    children: list[EvidenceNode] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class EvidenceTree(BaseModel):
    """Explainable proof tree for accepted and rejected hypotheses."""

    id: str = Field(default_factory=lambda: new_id("tree"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "reasoning_engine"
    run_id: str
    accepted_hypothesis: str
    state_path: list[str] = Field(default_factory=list)
    accepted_because: list[str] = Field(default_factory=list)
    rejected_alternatives: list[dict[str, str]] = Field(default_factory=list)
    root: EvidenceNode
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class ProofResult(BaseModel):
    """Result from an optional targeted proof check."""

    id: str = Field(default_factory=lambda: new_id("proof"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "proof_engine"
    hypothesis: str = ""
    status: ProofStatus = "NOT_RUN"
    confidence: ConfidenceScore = Field(default=0.0, ge=0.0, le=1.0)
    checks_run: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class ReliabilityImpact(BaseModel):
    """Explainable reliability impact ranking."""

    id: str = Field(default_factory=lambda: new_id("impact"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "impact_score"
    severity: ImpactSeverity
    scope: ImpactScope
    confidence: ConfidenceScore = Field(ge=0.0, le=1.0)
    duration_factor: ImpactDuration = "unknown"
    impact_score: float = Field(ge=0.0, le=1.0)
    impact_level: ImpactSeverity
    explanation: str
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class PolicyDecision(BaseModel):
    """Reasoning-aware policy decision for a requested remediation action."""

    id: str = Field(default_factory=lambda: new_id("policy"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "reasoning_policy"
    outcome: PolicyOutcome
    requested_action: str | None = None
    hypothesis: str = ""
    state_transition: str = ""
    evidence_level: EvidenceLevel = "inferred"
    proof_status: ProofStatus = "NOT_RUN"
    confidence: ConfidenceScore = Field(default=0.0, ge=0.0, le=1.0)
    trust_level: Literal["low", "medium", "high"] = "medium"
    impact_level: ImpactSeverity = "low"
    requires_confirmation: bool = False
    confirmation_phrase: str | None = None
    reason_codes: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)


class ReasoningRun(BaseModel):
    """Full replayable endpoint reasoning run."""

    id: str = Field(default_factory=lambda: new_id("run"))
    timestamp: str = Field(default_factory=utc_now_iso)
    source: str = "reasoning_engine"
    raw_observations: list[Observation] = Field(default_factory=list)
    normalized_signals: dict[str, Any] = Field(default_factory=dict)
    detected_events: list[EndpointEvent] = Field(default_factory=list)
    state_transitions: list[StateTransition] = Field(default_factory=list)
    canonical_state_path: list[str] = Field(default_factory=list)
    canonical_state_transitions: list[dict[str, Any]] = Field(default_factory=list)
    hypothesis_ranking: list[dict[str, Any]] = Field(default_factory=list)
    accepted_hypothesis: str = ""
    evidence_tree: EvidenceTree
    proof_result: ProofResult = Field(default_factory=ProofResult)
    reliability_impact: ReliabilityImpact
    policy_decision: PolicyDecision
    recommended_next_test: str = ""
    remediation_preview: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    audit_metadata: AuditMetadata = Field(default_factory=AuditMetadata)
    version_metadata: dict[str, str] = Field(
        default_factory=lambda: {"reasoning_schema": "reasoning.v1", "engine_version": "2026.05"}
    )

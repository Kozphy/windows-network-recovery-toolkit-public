"""Generic decision intelligence domain models.

Epistemic principle (non-negotiable):
    Observation != Proof
    Confidence != Certainty
    Research signal != execution permission

These models abstract the pipeline:
    Observation → Hypothesis → Evidence → Confidence → Policy → Audit → Replay
across endpoint reliability, market research, edge compute, and future domains.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from platform_core.models import utc_now_iso
from platform_core.reasoning_models import new_id

EvidenceKind = Literal[
    "observation",
    "hypothesis",
    "inference",
    "proof",
    "counter_evidence",
    "policy",
    "audit",
]

RiskSeverity = Literal["low", "medium", "high", "critical"]


class DecisionDomain(StrEnum):
    """Known decision domains; extensible via plain string on :class:`Decision`."""

    ENDPOINT_RELIABILITY = "endpoint_reliability"
    MARKET_EVENTS = "market_events"
    EDGE_COMPUTE = "edge_compute"
    GENERIC = "generic"


class DecisionEvidence(BaseModel):
    """Single evidence node attached to a decision."""

    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    label: str
    kind: EvidenceKind = "observation"
    detail: str = ""
    weight: float = Field(default=0.5, ge=0.0, le=1.0)
    supports_decision: bool | None = None
    source_ref: str = ""
    limitations: list[str] = Field(default_factory=list)


class DecisionContext(BaseModel):
    """Ambient context in which a decision is evaluated."""

    context_id: str = Field(default_factory=lambda: new_id("ctx"))
    domain: str
    subject_id: str = "local"
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    run_id: str = ""
    observation_refs: list[str] = Field(default_factory=list)
    hypothesis_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DecisionOption(BaseModel):
    """Alternative action or research path under consideration."""

    option_id: str = Field(default_factory=lambda: new_id("opt"))
    label: str
    description: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    risk_score: float = Field(ge=0.0, le=100.0, default=50.0)
    recommended: bool = False
    policy_gate: str = "PREVIEW"


class DecisionOutcome(BaseModel):
    """Expected or recorded outcome for the primary decision path."""

    outcome_id: str = Field(default_factory=lambda: new_id("out"))
    label: str
    description: str = ""
    success_likelihood: float | None = Field(default=None, ge=0.0, le=1.0)
    metrics: dict[str, Any] = Field(default_factory=dict)


class DecisionRisk(BaseModel):
    """Structured risk factor contributing to aggregate risk_score."""

    risk_id: str = Field(default_factory=lambda: new_id("risk"))
    category: str
    score: float = Field(ge=0.0, le=100.0)
    severity: RiskSeverity = "medium"
    description: str = ""
    mitigations: list[str] = Field(default_factory=list)


class DecisionExplanation(BaseModel):
    """Human- and machine-readable rationale for the decision."""

    summary: str
    main_drivers: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    policy_status: str = "PREVIEW"
    replay_ref: str = ""


class Decision(BaseModel):
    """Immutable decision snapshot for audit, replay, and cross-domain APIs."""

    decision_id: str = Field(default_factory=lambda: new_id("dec"))
    domain: str
    title: str
    evidence: list[DecisionEvidence] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    risk_score: float = Field(ge=0.0, le=100.0)
    expected_outcome: DecisionOutcome
    alternative_options: list[DecisionOption]
    context: DecisionContext | None = None
    risks: list[DecisionRisk] = Field(default_factory=list)
    explanation: DecisionExplanation | None = None
    schema_version: str = "decision_domain.v1"
    timestamp_utc: str = Field(default_factory=utc_now_iso)

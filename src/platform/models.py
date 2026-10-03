"""Canonical Multi-Domain Decision Platform models.

Single source of truth for: Event → Evidence → Hypothesis → Decision → Policy → Outcome.
Endpoint reliability models (``platform_core.evidence_model``, remediation) remain separate.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

DomainName = Literal["windows", "security", "cloud", "infrastructure", "market"]

PolicyStatus = Literal[
    "ALLOW_RESEARCH",
    "PREVIEW_ONLY",
    "BLOCK_LOW_CONFIDENCE",
    "BLOCK_AUTONOMOUS_ACTION",
    "BLOCK_DESTRUCTIVE_ACTION",
]

ActionType = Literal["research", "preview", "recommendation", "execute_like"]
EvidenceType = Literal["observation", "correlation", "proof", "counter_evidence"]
Severity = Literal["low", "medium", "high", "critical"]


class NormalizedEvent(BaseModel):
    """Represent normalized event data used by the toolkit.

    Attributes:
        event_id: Field or variant describing event id evidence or state.
        domain: Field or variant describing domain evidence or state.
        category: Field or variant describing category evidence or state.
        title: Field or variant describing title evidence or state.
        timestamp_utc: Field or variant describing timestamp utc evidence or state.
        severity: Field or variant describing severity evidence or state.
        observations: Field or variant describing observations evidence or state.
        source: Field or variant describing source evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    event_id: str
    domain: DomainName
    category: str
    title: str
    timestamp_utc: str
    severity: Severity = "medium"
    observations: list[dict[str, Any]] = Field(default_factory=list)
    source: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    """Represent evidence item data used by the toolkit.

    Attributes:
        evidence_id: Field or variant describing evidence id evidence or state.
        event_id: Field or variant describing event id evidence or state.
        type: Field or variant describing type evidence or state.
        description: Field or variant describing description evidence or state.
        supports: Field or variant describing supports evidence or state.
        contradicts: Field or variant describing contradicts evidence or state.
        confidence_delta: Field or variant describing confidence delta evidence or state.
        source: Field or variant describing source evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    evidence_id: str
    event_id: str
    type: EvidenceType = "observation"
    description: str
    supports: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    confidence_delta: float = Field(default=0.0, ge=-1.0, le=1.0)
    source: str = ""
    timestamp_utc: str = ""


class Hypothesis(BaseModel):
    """Represent hypothesis data used by the toolkit.

    Attributes:
        hypothesis_id: Field or variant describing hypothesis id evidence or state.
        event_id: Field or variant describing event id evidence or state.
        title: Field or variant describing title evidence or state.
        explanation: Field or variant describing explanation evidence or state.
        supporting_evidence: Field or variant describing supporting evidence evidence or state.
        contradicting_evidence: Field or variant describing contradicting evidence evidence or state.
        confidence: Field or variant describing confidence evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    hypothesis_id: str
    event_id: str
    title: str
    explanation: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class DecisionOption(BaseModel):
    """Represent decision option data used by the toolkit.

    Attributes:
        decision_id: Field or variant describing decision id evidence or state.
        event_id: Field or variant describing event id evidence or state.
        title: Field or variant describing title evidence or state.
        action_type: Field or variant describing action type evidence or state.
        expected_benefit: Field or variant describing expected benefit evidence or state.
        risk_score: Field or variant describing risk score evidence or state.
        confidence: Field or variant describing confidence evidence or state.
        alternatives: Field or variant describing alternatives evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    decision_id: str
    event_id: str
    title: str
    action_type: ActionType = "recommendation"
    expected_benefit: float = Field(default=0.5, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.2, ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    alternatives: list[str] = Field(default_factory=list)
    policy_status: PolicyStatus = "PREVIEW_ONLY"
    explanation: str = ""
    final_score: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(BaseModel):
    """Policy gate result — permission is not a safety guarantee."""

    status: PolicyStatus
    execute_allowed: bool = False
    preview_allowed: bool = True
    reasons: list[str] = Field(default_factory=list)
    explanation: str = ""


class DecisionOutcome(BaseModel):
    """Represent decision outcome data used by the toolkit.

    Attributes:
        outcome_id: Field or variant describing outcome id evidence or state.
        decision_id: Field or variant describing decision id evidence or state.
        success: Field or variant describing success evidence or state.
        observed_result: Field or variant describing observed result evidence or state.
        cost_score: Field or variant describing cost score evidence or state.
        time_to_resolution_seconds: Field or variant describing time to resolution seconds evidence or state.
        lessons_learned: Field or variant describing lessons learned evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    outcome_id: str
    decision_id: str
    success: bool
    observed_result: str = ""
    cost_score: float = Field(default=0.0, ge=0.0, le=1.0)
    time_to_resolution_seconds: float = Field(default=0.0, ge=0.0)
    lessons_learned: str = ""

"""Pydantic agent output contracts — deterministic interchange, not autonomous execution."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class EvidenceAgentOutput(BaseModel):
    """Represent the evidence agent output type.

    Key fields:
        event_id: Structured value carried by this type.
        endpoint_id: Structured value carried by this type.
        evidence_type: Structured value carried by this type.
        evidence_tier: Structured value carried by this type.
        raw_snapshot: Structured value carried by this type.
        limitations: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    event_id: str
    endpoint_id: str
    evidence_type: str
    evidence_tier: str = "T1_STATE_EVIDENCE"
    raw_snapshot: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class ClassificationAgentOutput(BaseModel):
    """Represent the classification agent output type.

    Key fields:
        incident_id: Structured value carried by this type.
        primary_classification: Structured value carried by this type.
        proof_tier: Structured value carried by this type.
        confidence: Structured value carried by this type.
        secondary_signals: Structured value carried by this type.
        limitations: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    incident_id: str
    primary_classification: str
    proof_tier: str
    confidence: float = Field(ge=0.0, le=1.0)
    secondary_signals: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RootCauseAgentOutput(BaseModel):
    """Represent the root cause agent output type.

    Key fields:
        incident_id: Structured value carried by this type.
        hypotheses: Structured value carried by this type.
        limitations: Structured value carried by this type.

    Side effects:
        None.
    """
    incident_id: str
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RiskAssessmentAgentOutput(BaseModel):
    """Represent the risk assessment agent output type.

    Key fields:
        incident_id: Structured value carried by this type.
        risk_score: Structured value carried by this type.
        risk_level: Structured value carried by this type.
        human_review_recommended: Structured value carried by this type.
        limitations: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    incident_id: str
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_level: str
    human_review_recommended: bool = False
    limitations: list[str] = Field(default_factory=list)


class ControlValidationAgentOutput(BaseModel):
    """Represent the control validation agent output type.

    Key fields:
        incident_id: Structured value carried by this type.
        control_tests: Structured value carried by this type.
        limitations: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    incident_id: str
    control_tests: list[dict[str, Any]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ReportingAgentOutput(BaseModel):
    """Represent the reporting agent output type.

    Key fields:
        report_type: Structured value carried by this type.
        kpis: Structured value carried by this type.
        limitations: Structured value carried by this type.

    Side effects:
        None.
    """
    report_type: str = "executive"
    kpis: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)

"""Typed contracts for policy-gated agentic recovery.

The agent layer reasons over existing deterministic evidence and decision outputs. It never
executes Windows mutations directly; execution remains owned by existing remediation code.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from windows_network_toolkit.decision.decision_model import IncidentType


class AgentStage(StrEnum):
    DIAGNOSE = "DIAGNOSE"
    PLAN = "PLAN"
    POLICY = "POLICY"
    VERIFY = "VERIFY"
    STOP = "STOP"
    ESCALATE = "ESCALATE"


class AgentDisposition(StrEnum):
    PREVIEW_READY = "PREVIEW_READY"
    AWAIT_CONFIRMATION = "AWAIT_CONFIRMATION"
    BLOCKED = "BLOCKED"
    ESCALATE = "ESCALATE"
    STOP = "STOP"


class AgentDiagnosis(BaseModel):
    incident_type: IncidentType
    confidence: float = Field(ge=0.0, le=1.0)
    hypothesis: str
    evidence_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    human_review_required: bool = False


class RepairStep(BaseModel):
    action: str
    purpose: str
    mutates_state: bool = False
    requires_confirmation: bool = False
    rollback: str = ""


class RepairPlan(BaseModel):
    incident_id: str
    diagnosis: AgentDiagnosis
    steps: list[RepairStep] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    retry_budget: int = Field(default=1, ge=0, le=3)
    stopping_conditions: list[str] = Field(default_factory=list)


class AgentRunResult(BaseModel):
    incident_id: str
    decision_id: str
    stage: AgentStage
    disposition: AgentDisposition
    plan: RepairPlan
    policy: dict[str, Any]
    audit_events: list[dict[str, Any]] = Field(default_factory=list)

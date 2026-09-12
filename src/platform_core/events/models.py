"""Technology-risk domain event models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from platform_core.reasoning_models import new_id


def _utc_now_iso() -> str:
    from platform_core.models import utc_now_iso

    return utc_now_iso()


class TriskEventType(StrEnum):
    """Represent the trisk event type enum.

    Variants:
        EVIDENCE_COLLECTED: Structured value carried by this enum.
        INCIDENT_DETECTED: Structured value carried by this enum.
        RISK_CLASSIFIED: Structured value carried by this enum.
        CONTROL_TEST_COMPLETED: Structured value carried by this enum.
        HUMAN_APPROVAL_GRANTED: Structured value carried by this enum.
        GOVERNANCE_REPORT_GENERATED: Structured value carried by this enum.
        MCP_TOOL_INVOKED: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    EVIDENCE_COLLECTED = "EvidenceCollected"
    INCIDENT_DETECTED = "IncidentDetected"
    RISK_CLASSIFIED = "RiskClassified"
    CONTROL_TEST_COMPLETED = "ControlTestCompleted"
    HUMAN_APPROVAL_GRANTED = "HumanApprovalGranted"
    GOVERNANCE_REPORT_GENERATED = "GovernanceReportGenerated"
    MCP_TOOL_INVOKED = "McpToolInvoked"


TriskAggregateType = Literal["evidence", "incident", "report", "mcp"]


class TriskDomainEvent(BaseModel):
    """Append-only domain event envelope for the trisk loop."""

    event_id: str = Field(default_factory=lambda: new_id("devt"))
    event_type: TriskEventType
    aggregate_id: str
    aggregate_type: TriskAggregateType = "evidence"
    sequence: int = Field(ge=1)
    timestamp_utc: str = Field(default_factory=_utc_now_iso)
    actor: str = "system"
    correlation_id: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)

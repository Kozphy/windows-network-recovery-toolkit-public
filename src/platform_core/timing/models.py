"""Immutable timing models — urgency, SLA, windows; not execution authorization.

A valid maintenance window is not execution authorization.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_TIMING = "timing_context.v1"


class Urgency(StrEnum):
    """Represent the urgency enum.

    Variants:
        LOW: Structured value carried by this enum.
        MEDIUM: Structured value carried by this enum.
        HIGH: Structured value carried by this enum.
        CRITICAL: Structured value carried by this enum.

    Side effects:
        None.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TimingDecision(StrEnum):
    """Represent the timing decision enum.

    Variants:
        READY: Structured value carried by this enum.
        ESCALATE_NOW: Structured value carried by this enum.
        MONITOR_UNTIL: Structured value carried by this enum.
        DEFERRED_TO_WINDOW: Structured value carried by this enum.
        BLOCKED_BY_CHANGE_FREEZE: Structured value carried by this enum.
        EVIDENCE_EXPIRED: Structured value carried by this enum.
        SLA_OVERDUE: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    READY = "READY"
    ESCALATE_NOW = "ESCALATE_NOW"
    MONITOR_UNTIL = "MONITOR_UNTIL"
    DEFERRED_TO_WINDOW = "DEFERRED_TO_WINDOW"
    BLOCKED_BY_CHANGE_FREEZE = "BLOCKED_BY_CHANGE_FREEZE"
    EVIDENCE_EXPIRED = "EVIDENCE_EXPIRED"
    SLA_OVERDUE = "SLA_OVERDUE"


class TimingReasonCode(StrEnum):
    """Represent the timing reason code enum.

    Variants:
        WITHIN_SLA: Structured value carried by this enum.
        SLA_BREACHED: Structured value carried by this enum.
        EVIDENCE_VALID: Structured value carried by this enum.
        EVIDENCE_STALE: Structured value carried by this enum.
        IN_MAINTENANCE_WINDOW: Structured value carried by this enum.
        OUTSIDE_MAINTENANCE_WINDOW: Structured value carried by this enum.
        CHANGE_FREEZE_ACTIVE: Structured value carried by this enum.
        BUSINESS_HOURS: Structured value carried by this enum.

    Side effects:
        None.
    """

    WITHIN_SLA = "WITHIN_SLA"
    SLA_BREACHED = "SLA_BREACHED"
    EVIDENCE_VALID = "EVIDENCE_VALID"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    IN_MAINTENANCE_WINDOW = "IN_MAINTENANCE_WINDOW"
    OUTSIDE_MAINTENANCE_WINDOW = "OUTSIDE_MAINTENANCE_WINDOW"
    CHANGE_FREEZE_ACTIVE = "CHANGE_FREEZE_ACTIVE"
    BUSINESS_HOURS = "BUSINESS_HOURS"
    AFTER_HOURS = "AFTER_HOURS"
    HIGH_URGENCY_ESCALATION = "HIGH_URGENCY_ESCALATION"
    RETRY_AFTER_SET = "RETRY_AFTER_SET"


class TimingContext(BaseModel):
    """Represent the timing context type.

    Key fields:
        schema_version: Structured value carried by this type.
        case_id: Structured value carried by this type.
        detected_at_utc: Structured value carried by this type.
        evaluated_at_utc: Structured value carried by this type.
        timezone: Structured value carried by this type.
        clock_source: Structured value carried by this type.
        urgency: Structured value carried by this type.
        action_window_start_utc: Structured value carried by this type.

    Side effects:
        None.
    """

    model_config = ConfigDict(frozen=True)

    schema_version: str = SCHEMA_TIMING
    case_id: str = ""
    detected_at_utc: str
    evaluated_at_utc: str
    timezone: str
    clock_source: str = "UTC"
    urgency: Urgency = Urgency.MEDIUM
    action_window_start_utc: str | None = None
    action_window_end_utc: str | None = None
    sla_due_utc: str | None = None
    evidence_expires_utc: str | None = None
    retry_after_utc: str | None = None
    maintenance_window_required: bool = False
    in_maintenance_window: bool | None = None
    change_freeze_active: bool = False
    business_hours: bool | None = None
    decision: TimingDecision = TimingDecision.READY
    reason_codes: tuple[TimingReasonCode, ...] = ()
    limitations: tuple[str, ...] = (
        "A valid maintenance window is not execution authorization.",
        "High urgency never bypasses typed confirmation.",
        "Timezone must be supplied explicitly; platform core defaults to UTC.",
    )
    inputs_fingerprint: str = ""
    config_refs: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.
        """
        return self.model_dump(mode="json")


BusinessHoursSpec = dict[str, Any]  # documented in windows.py

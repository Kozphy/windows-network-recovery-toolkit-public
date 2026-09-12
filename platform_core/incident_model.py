"""Incident lifecycle models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from platform_core.models import utc_now_iso

IncidentState = Literal["OPEN", "ACKNOWLEDGED", "MITIGATED", "RESOLVED", "FALSE_POSITIVE"]
IncidentSeverity = Literal["low", "medium", "high", "critical"]


class IncidentRecord(BaseModel):
    """Represent IncidentRecord data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    incident_id: str
    endpoint_id: str = ""
    title: str = ""
    state: IncidentState = "OPEN"
    severity: IncidentSeverity = "medium"
    evidence_level: str = "inference"
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    signals: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

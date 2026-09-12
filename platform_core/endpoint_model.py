"""Endpoint record model for fleet visibility."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from platform_core.models import utc_now_iso

RiskState = Literal["healthy", "degraded", "incident_open", "unknown"]


class EndpointRecord(BaseModel):
    """Represent EndpointRecord data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    endpoint_id: str
    hostname: str = ""
    os_name: str = ""
    agent_version: str = ""
    first_seen: str = Field(default_factory=utc_now_iso)
    last_seen: str = Field(default_factory=utc_now_iso)
    latest_snapshot_id: str = ""
    latest_diagnosis_id: str = ""
    risk_state: RiskState = "unknown"

    def to_summary_row(self) -> dict[str, str]:
        """Return a serialized to summary row representation.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return {
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "agent_version": self.agent_version,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "latest_snapshot_id": self.latest_snapshot_id,
            "latest_diagnosis_id": self.latest_diagnosis_id,
            "risk_state": self.risk_state,
        }

"""Proxy registry writer attribution models — observation != certainty."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from .models import AttributionSnapshot, ProcessAttribution


class AttributionConfidence(StrEnum):
    """Ordinal confidence — not a probability."""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class RegistryWriterEvidence(BaseModel):
    """Evidence that a process wrote a monitored WinINET proxy registry value."""

    source: str  # sysmon_e13 | etw_registry | procmon | fixture
    event_id: int | None = None
    timestamp_utc: str = ""
    target_object: str = ""
    value_name: str = ""
    details: str = ""
    process_name: str = ""
    pid: int | None = None
    ppid: int | None = None
    parent_process_name: str = ""
    command_line: str = ""
    parent_command_line: str = ""
    executable_path: str = ""
    signature_status: str = ""
    sha256: str = ""
    process_guid: str = ""
    details_match: bool = False


class ProxyWriterAttributionResult(BaseModel):
    """Unified proxy writer attribution — never claims certainty without writer proof."""

    attribution_id: str
    timestamp_utc: str
    snapshot: AttributionSnapshot
    registry_monitored: list[str] = Field(
        default_factory=lambda: [
            "ProxyEnable",
            "ProxyServer",
            "ProxyOverride",
            "AutoConfigURL",
        ]
    )
    registry_state: dict[str, Any] = Field(default_factory=dict)
    writer_evidence: list[RegistryWriterEvidence] = Field(default_factory=list)
    registry_writer_confirmed: bool = False
    correlated_process: ProcessAttribution = Field(default_factory=ProcessAttribution)
    attribution_confidence: AttributionConfidence = AttributionConfidence.LOW
    confidence_score: float = 0.0
    classification: str = ""
    rationale: str = ""
    limitations: list[str] = Field(default_factory=list)
    telemetry_sources: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return to dict.

        Returns:
            The computed `dict[str, Any]` value.

        Side effects:
            None.
        """
        return self.model_dump(mode="json")

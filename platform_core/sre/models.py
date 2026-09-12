"""SRE domain event models — canonical event-sourcing envelope."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from platform_core.reasoning_models import new_id


def _utc_now_iso() -> str:
    from platform_core.models import utc_now_iso

    return utc_now_iso()


DomainEventType = Literal[
    "incident.detected",
    "incident.acknowledged",
    "incident.investigation_started",
    "incident.hypothesis_ranked",
    "incident.root_cause_identified",
    "incident.mitigation_attempted",
    "incident.resolved",
    "incident.false_positive",
    "telemetry.normalized",
    "state.transitioned",
    "decision.recorded",
    "audit.signed",
    "domain.circuit_opened",
    "domain.circuit_closed",
    "postmortem.generated",
]

FailureDomainName = Literal[
    "telemetry_ingest",
    "state_machine",
    "hypothesis_engine",
    "policy_engine",
    "remediation",
    "audit",
    "investigation",
]


class DomainEvent(BaseModel):
    """Immutable domain event — append-only, globally ordered within aggregate."""

    event_id: str = Field(default_factory=lambda: new_id("devt"))
    sequence: int = Field(ge=1, description="Monotonic per aggregate_id")
    aggregate_id: str
    aggregate_type: Literal["incident", "endpoint", "decision", "audit"] = "incident"
    event_type: DomainEventType
    timestamp_utc: str = Field(default_factory=_utc_now_iso)
    correlation_id: str = Field(description="Incident or investigation correlation id")
    causation_id: str | None = Field(
        default=None, description="Parent event_id that caused this event"
    )
    failure_domain: FailureDomainName | None = None
    actor: str = "system"
    payload: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = "sre.domain_event.v1"

    def content_hash_input(self) -> dict[str, Any]:
        """Fields included in audit hash (excludes event_id for idempotency checks)."""
        return {
            "sequence": self.sequence,
            "aggregate_id": self.aggregate_id,
            "aggregate_type": self.aggregate_type,
            "event_type": self.event_type,
            "timestamp_utc": self.timestamp_utc,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
        }


class IncidentPhase(str, Enum):
    """Incident lifecycle — transitions are event-sourced, not mutable state."""

    DETECTED = "DETECTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    ROOT_CAUSE_IDENTIFIED = "ROOT_CAUSE_IDENTIFIED"
    MITIGATING = "MITIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentProjection(BaseModel):
    """Read model rebuilt deterministically from domain events."""

    incident_id: str
    endpoint_id: str
    phase: IncidentPhase = IncidentPhase.DETECTED
    title: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    detected_at: str = ""
    acknowledged_at: str | None = None
    investigation_started_at: str | None = None
    root_cause_identified_at: str | None = None
    resolved_at: str | None = None
    accepted_hypothesis: str | None = None
    root_cause_summary: str | None = None
    evidence_event_ids: list[str] = Field(default_factory=list)
    decision_run_ids: list[str] = Field(default_factory=list)
    state_path: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    event_count: int = 0
    last_sequence: int = 0


class TimelineEntry(BaseModel):
    """Single row in incident timeline reconstruction."""

    sequence: int
    timestamp_utc: str
    event_type: str
    event_id: str
    summary: str
    failure_domain: str | None = None
    causation_id: str | None = None
    payload_excerpt: dict[str, Any] = Field(default_factory=dict)


class RCAReport(BaseModel):
    """Evidence-driven root cause analysis — not a conviction."""

    incident_id: str
    root_cause_statement: str
    confidence_tier: Literal["observation", "correlated", "contrast_tested", "proven"] = (
        "observation"
    )
    accepted_hypothesis: str | None = None
    supporting_evidence: list[dict[str, Any]] = Field(default_factory=list)
    rejected_hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    causal_chain: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class PostmortemDocument(BaseModel):
    """Structured postmortem — blameless, audit-linked."""

    postmortem_id: str = Field(default_factory=lambda: new_id("pm"))
    incident_id: str
    generated_at: str = Field(default_factory=_utc_now_iso)
    title: str
    severity: str
    duration_seconds: float | None = None
    mttd_seconds: float | None = None
    mttr_seconds: float | None = None
    mtti_seconds: float | None = None
    summary: str
    timeline_markdown: str
    root_cause_markdown: str
    impact: str
    what_went_well: list[str] = Field(default_factory=list)
    what_went_wrong: list[str] = Field(default_factory=list)
    action_items: list[dict[str, str]] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    correlation_id: str = ""

    def to_markdown(self) -> str:
        """Return a serialized to markdown representation.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        went_well = [f"- {w}" for w in self.what_went_well] or ["- (none recorded)"]
        went_wrong = [f"- {w}" for w in self.what_went_wrong] or ["- (none recorded)"]
        lines = [
            f"# Postmortem: {self.title}",
            "",
            f"**Incident ID:** `{self.incident_id}`  ",
            f"**Postmortem ID:** `{self.postmortem_id}`  ",
            f"**Generated:** {self.generated_at}  ",
            f"**Severity:** {self.severity}  ",
            "",
            "## Summary",
            self.summary,
            "",
            "## Impact",
            self.impact,
            "",
            "## Reliability metrics",
            f"- MTTD: {self.mttd_seconds}s" if self.mttd_seconds is not None else "- MTTD: n/a",
            f"- MTTI (time to identify): {self.mtti_seconds}s"
            if self.mtti_seconds is not None
            else "- MTTI: n/a",
            f"- MTTR: {self.mttr_seconds}s" if self.mttr_seconds is not None else "- MTTR: n/a",
            f"- Duration: {self.duration_seconds}s"
            if self.duration_seconds is not None
            else "- Duration: n/a",
            "",
            "## Timeline",
            self.timeline_markdown,
            "",
            "## Root cause analysis",
            self.root_cause_markdown,
            "",
            "## What went well",
            *went_well,
            "",
            "## What went wrong",
            *went_wrong,
            "",
            "## Action items",
        ]
        if self.action_items:
            lines.append("| Owner | Action | Priority |")
            lines.append("| --- | --- | --- |")
            for item in self.action_items:
                lines.append(
                    f"| {item.get('owner', 'TBD')} | {item.get('action', '')} | {item.get('priority', 'P2')} |"
                )
        else:
            lines.append("- (none — investigation incomplete or false positive)")
        if self.limitations:
            lines.extend(
                ["", "## Epistemic limitations", *[f"- {lim}" for lim in self.limitations]]
            )
        return "\n".join(lines) + "\n"


class MTTRMetrics(BaseModel):
    """Incident-lifecycle-derived reliability metrics (not fixture estimates)."""

    incident_count: int = 0
    resolved_count: int = 0
    mean_time_to_detect_seconds: float | None = None
    mean_time_to_identify_seconds: float | None = None
    mean_time_to_recover_seconds: float | None = None
    p50_mttr_seconds: float | None = None
    p95_mttr_seconds: float | None = None
    false_positive_rate: float | None = None
    investigation_count: int = 0

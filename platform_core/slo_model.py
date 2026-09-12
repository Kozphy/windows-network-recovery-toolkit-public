"""SLO and reliability metric models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReliabilityMetrics(BaseModel):
    """Represent ReliabilityMetrics data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    browser_path_success_rate: float = Field(ge=0.0, le=1.0, default=0.0)
    proxy_drift_events_per_day: float = Field(ge=0.0, default=0.0)
    mean_time_to_detect_seconds: float | None = None
    mean_time_to_recover_seconds: float | None = None
    remediation_stickiness_rate: float = Field(ge=0.0, le=1.0, default=0.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0, default=0.0)


class SloMetrics(BaseModel):
    """SRE-style reliability KPIs derived from append-only JSONL."""

    mean_time_to_detect_seconds: float | None = None
    mean_time_to_explain_seconds: float | None = None
    proxy_drift_incidents_total: int = Field(ge=0, default=0)
    blocked_high_risk_action_count: int = Field(ge=0, default=0)
    remediation_preview_count: int = Field(ge=0, default=0)
    proof_unavailable_rate: float = Field(ge=0.0, le=1.0, default=0.0)
    final_causation_rate: float = Field(ge=0.0, le=1.0, default=0.0)
    reliability: ReliabilityMetrics = Field(default_factory=ReliabilityMetrics)

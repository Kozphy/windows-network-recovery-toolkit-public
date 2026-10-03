"""Canonical proxy entity and reasoning run models.

Observation ≠ Inference ≠ Proof. Models separate attribute groups so downstream
renderers never collapse heuristic attribution into forensic claims.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, Field

from proxy_reasoning.constants import (
    SCHEMA_VERSION,
    ConclusionStrength,
    ConfidenceRank,
    EvidenceLevel,
    PolicyOutcome,
    ProxyClassification,
    RiskLevel,
    VerificationStatus,
)


def new_id(prefix: str) -> str:
    """Create a short typed identifier."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class ConfigurationAttributes(BaseModel):
    """Registry and config-surface observations."""

    source: Literal["WinINET", "WinHTTP", "env", "browser", "PAC", "mixed", "unknown"] = "unknown"
    proxy_enable: bool | None = None
    proxy_server: str | None = None
    autoconfig_url: str | None = None
    bypass_list: str | None = None
    scope: Literal["user", "machine", "process", "unknown"] = "unknown"
    observed_at: str = ""
    winhttp_direct: bool | None = None
    wininet_winhttp_divergent: bool | None = None


class NetworkAttributes(BaseModel):
    """Reachability and transport observations for the configured proxy path."""

    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    is_loopback: bool = False
    is_remote: bool = False
    dns_resolution_state: Literal["ok", "failed", "unknown"] = "unknown"
    tcp_reachability: Literal["ok", "failed", "unknown"] = "unknown"
    tls_behavior: Literal["ok", "failed", "unknown"] = "unknown"
    connect_method_supported: bool | None = None
    latency_ms: float | None = None
    listener_present: bool | None = None


class ProcessAttributionAttributes(BaseModel):
    """Heuristic listener correlation — not registry-writer proof."""

    pid: int | None = None
    process_name: str | None = None
    executable_path: str | None = None
    command_line: str | None = None
    parent_pid: int | None = None
    signer: str | None = None
    start_time: str | None = None
    attribution_confidence: ConfidenceRank = "low"
    attribution_limitations: list[str] = Field(default_factory=list)


class BehavioralAttributes(BaseModel):
    """Temporal and path-behavior observations."""

    persistent: bool | None = None
    intermittent: bool | None = None
    reappears_after_reboot: bool | None = None
    reappears_after_app_start: bool | None = None
    affects_browser: bool | None = None
    affects_electron_apps: bool | None = None
    curl_works: bool | None = None
    browser_works: bool | None = None
    app_fails: bool | None = None
    last_known_good_state: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    firewall_reset_helped: bool | None = None


class TrustRiskAttributes(BaseModel):
    """Bounded classification — never implies malicious intent without proof tier."""

    classification: ProxyClassification = "NO_PROXY"
    risk_level: RiskLevel = "low"
    rationale: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    """Single evidence row supporting or contradicting a hypothesis."""

    id: str = Field(default_factory=lambda: new_id("ev"))
    label: str
    evidence_level: EvidenceLevel = "observed"
    supports_hypothesis: str | None = None
    contradicts_hypothesis: str | None = None
    detail: str = ""


class EvidenceAttributes(BaseModel):
    """Aggregated evidence boundary for a reasoning run."""

    evidence_items: list[EvidenceItem] = Field(default_factory=list)
    supports: list[str] = Field(default_factory=list)
    contradicts: list[str] = Field(default_factory=list)
    verification_status: VerificationStatus = "UNVERIFIED"
    confidence_boundary: ConfidenceRank = "low"
    reproducibility: Literal["unknown", "single_observation", "repeatable"] = "unknown"
    conclusion_strength: ConclusionStrength = "weak"


class PolicyAttributes(BaseModel):
    """Policy outcome separated from diagnosis."""

    decision: PolicyOutcome = "PREVIEW"
    matched_rule: str = ""
    reason: str = ""
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    requires_human_review: bool = True


class ProxyEntity(BaseModel):
    """First-class proxy profile with structured attribute groups."""

    entity_id: str = Field(default_factory=lambda: new_id("proxy"))
    configuration_attributes: ConfigurationAttributes = Field(
        default_factory=ConfigurationAttributes
    )
    network_attributes: NetworkAttributes = Field(default_factory=NetworkAttributes)
    process_attribution_attributes: ProcessAttributionAttributes = Field(
        default_factory=ProcessAttributionAttributes,
    )
    behavioral_attributes: BehavioralAttributes = Field(default_factory=BehavioralAttributes)
    trust_risk_attributes: TrustRiskAttributes = Field(default_factory=TrustRiskAttributes)
    evidence_attributes: EvidenceAttributes = Field(default_factory=EvidenceAttributes)
    policy_attributes: PolicyAttributes = Field(default_factory=PolicyAttributes)


class ProxySignal(BaseModel):
    """Raw observation — no inference."""

    name: str
    value: Any
    source: str = "collector"
    observed_at: str = ""


class ProxyEvent(BaseModel):
    """Structured state transition derived from signals."""

    id: str = Field(default_factory=lambda: new_id("evt"))
    event_type: str
    severity: Literal["info", "low", "medium", "high"] = "info"
    signal_names: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class ProxyHypothesis(BaseModel):
    """Possible explanation — not a proven fact."""

    case_id: str
    title: str
    confidence_rank: ConfidenceRank = "low"
    evidence_level: EvidenceLevel = "inferred"
    supporting_signals: list[str] = Field(default_factory=list)
    contradicting_signals: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    rejected: bool = False
    rejection_reason: str = ""


class VerificationResult(BaseModel):
    """Operational verification — confirms behavior, not intent."""

    check_id: str
    status: VerificationStatus = "UNVERIFIED"
    hypothesis_scope: str = ""
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ConfidenceBoundary(BaseModel):
    """Ordinal confidence cap — not a calibrated probability."""

    rank: ConfidenceRank = "low"
    rationale: str = ""
    caps: list[str] = Field(default_factory=list)


class ProxyReasoningRun(BaseModel):
    """Full replayable proxy reasoning run."""

    run_id: str = Field(default_factory=lambda: new_id("run"))
    timestamp: str = ""
    schema_version: str = SCHEMA_VERSION
    engine_version: str = "2026.05"
    entity: ProxyEntity
    signals: list[ProxySignal] = Field(default_factory=list)
    events: list[ProxyEvent] = Field(default_factory=list)
    hypotheses: list[ProxyHypothesis] = Field(default_factory=list)
    accepted_hypothesis: str = ""
    evidence_tree: dict[str, Any] = Field(default_factory=dict)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    confidence_boundary: ConfidenceBoundary = Field(default_factory=ConfidenceBoundary)
    policy_decision: PolicyAttributes = Field(default_factory=PolicyAttributes)
    limitations: list[str] = Field(default_factory=list)
    user_visible_summary: dict[str, Any] = Field(default_factory=dict)
    requested_action: str | None = None

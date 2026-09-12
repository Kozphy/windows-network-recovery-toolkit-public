"""Typed models for the production reliability platform.

Epistemic principle (non-negotiable):
    Observation != Proof
    Correlation != Causation
    Confidence != Certainty
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from platform_core.models import utc_now_iso
from platform_core.reasoning_models import new_id

EventSourceKind = Literal[
    "registry",
    "sysmon",
    "etw",
    "windows_event_log",
    "network_telemetry",
    "agent",
    "cli",
    "replay",
    "fixture",
]

EvidenceNodeKind = Literal[
    "process",
    "registry_write",
    "listener",
    "network_flow",
    "policy_decision",
    "observation",
    "hypothesis",
]

HypothesisCategory = Literal[
    "known_developer_tool",
    "security_product",
    "misconfiguration",
    "potential_malware",
    "unknown",
]

PolicyOutcome = Literal["ALLOW", "PREVIEW", "BLOCK"]


class NormalizedPlatformEvent(BaseModel):
    """Append-only normalized event from any telemetry source."""

    event_id: str = Field(default_factory=lambda: new_id("evt"))
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    endpoint_id: str = "local"
    source_kind: EventSourceKind
    source_detail: str = ""
    signal_name: str
    signal_value: Any = None
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    evidence_tier: Literal[
        "TIER_0_RAW_OBSERVATION",
        "TIER_1_CORRELATED_SIGNAL",
        "TIER_2_CONTRAST_TESTED",
        "TIER_3_CAUSAL_PROOF",
    ] = "TIER_0_RAW_OBSERVATION"
    observation_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)
    schema_version: str = "platform_event.v1"


class PlatformStateTransition(BaseModel):
    """Deterministic state transition record."""

    transition_id: str = Field(default_factory=lambda: new_id("trans"))
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    endpoint_id: str = "local"
    from_state: str
    to_state: str
    rule_id: str
    triggering_event_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    replayable: bool = True


class EvidenceGraphNode(BaseModel):
    """Node in the causal evidence graph."""

    node_id: str = Field(default_factory=lambda: new_id("node"))
    kind: EvidenceNodeKind
    label: str
    strength: Literal["weak", "medium", "strong", "proof"] = "weak"
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    event_ids: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)


class EvidenceGraphEdge(BaseModel):
    """Directed causal/support edge between evidence nodes."""

    edge_id: str = Field(default_factory=lambda: new_id("edge"))
    from_node_id: str
    to_node_id: str
    relation: Literal["supports", "contradicts", "caused_by", "correlates_with"] = "supports"
    weight: float = Field(default=0.5, ge=0.0, le=1.0)


class RankedHypothesis(BaseModel):
    """Weighted hypothesis with ordinal confidence (not probability)."""

    hypothesis_id: str
    category: HypothesisCategory
    label: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_node_ids: list[str] = Field(default_factory=list)
    supporting_signals: list[str] = Field(default_factory=list)
    rejected_reason: str | None = None


class PlatformDecisionRecord(BaseModel):
    """Immutable decision snapshot for audit + replay."""

    decision_id: str = Field(default_factory=lambda: new_id("dec"))
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    endpoint_id: str = "local"
    run_id: str = ""
    state_path: list[str] = Field(default_factory=list)
    accepted_hypothesis: str = ""
    hypothesis_ranking: list[dict[str, Any]] = Field(default_factory=list)
    policy_outcome: PolicyOutcome = "PREVIEW"
    policy_reason_codes: list[str] = Field(default_factory=list)
    evidence_graph_summary: dict[str, Any] = Field(default_factory=dict)
    event_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    audit_signature: str | None = None
    schema_version: str = "platform_decision.v1"


class PlatformState(str, Enum):
    """Production endpoint reliability states."""

    NORMAL = "NORMAL"
    LOCAL_PROXY_ENABLED = "LOCAL_PROXY_ENABLED"
    PROXY_FAILURE = "PROXY_FAILURE"
    BYPASS_SUCCESS = "BYPASS_SUCCESS"
    ROOT_CAUSE_IDENTIFIED = "ROOT_CAUSE_IDENTIFIED"
    DEGRADED = "DEGRADED"
    BROKEN = "BROKEN"
    RECOVERING = "RECOVERING"

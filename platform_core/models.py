"""Typed platform domain models (Pydantic). All timestamps are UTC ISO-8601 strings."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    """Timezone-aware UTC ISO string for JSON serialization."""
    return datetime.now(UTC).isoformat()


RiskLevel = Literal["read_only", "low", "medium", "high", "forbidden"]
FailureSeverity = Literal["low", "medium", "high"]
FailureCategory = Literal[
    "dns",
    "proxy",
    "tcp_tls",
    "browser_path",
    "winsock",
    "firewall",
    "adapter",
    "unknown",
]
FailureStatus = Literal["open", "acknowledged", "remediated", "ignored", "false_positive"]
RequestSurface = Literal["api", "cli", "dashboard"]


class EndpointIdentity(BaseModel):
    """Sanitized endpoint registration (no raw hostname)."""

    endpoint_id: str = Field(description="Stable hashed identifier (hex prefix).")
    os_family: str = ""
    os_version: str = ""
    agent_version: str = ""
    created_at: str = Field(default_factory=utc_now_iso)
    last_seen_at: str = Field(default_factory=utc_now_iso)


class EndpointSnapshot(BaseModel):
    """Single diagnostic capture after privacy normalization."""

    endpoint_id: str
    collected_at: str = Field(default_factory=utc_now_iso)
    network_state: dict[str, Any] = Field(default_factory=dict)
    proxy_state: dict[str, Any] = Field(default_factory=dict)
    dns_state: dict[str, Any] = Field(default_factory=dict)
    tcp_state: dict[str, Any] = Field(default_factory=dict)
    browser_path_state: dict[str, Any] = Field(default_factory=dict)
    process_clues: dict[str, Any] = Field(default_factory=dict)
    raw_data_redacted: bool = True


class FailureEvent(BaseModel):
    """Operational event linking diagnosis to knowledge base."""

    event_id: str
    endpoint_id: str
    failure_block_id: str = ""
    severity: FailureSeverity = "low"
    category: FailureCategory = "unknown"
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    first_seen_at: str = Field(default_factory=utc_now_iso)
    last_seen_at: str = Field(default_factory=utc_now_iso)
    status: FailureStatus = "open"
    summary: str = ""
    recommended_action_key: str = ""


class RemediationPolicy(BaseModel):
    """Declarative policy bundle (can be loaded from JSON later)."""

    policy_id: str = "default"
    name: str = "Local prototype policy"
    allowed_risk_levels: list[RiskLevel] = Field(
        default_factory=lambda: ["read_only", "low", "medium"],
    )
    forbidden_actions: list[str] = Field(default_factory=list)
    requires_confirmation: bool = True
    requires_admin: bool = False
    can_run_from_api: bool = True
    can_run_from_cli: bool = True
    rollback_required: bool = False


class RollbackPreviewFields(BaseModel):
    """Structured rollback preview (preview-only; does not execute mutations)."""

    rollback_preview_id: str = ""
    pre_change_snapshot: dict[str, Any] = Field(default_factory=dict)
    proposed_mutation_preview: dict[str, Any] = Field(default_factory=dict)
    human_approval_token_required: bool = True
    reversible_action_record: dict[str, Any] = Field(default_factory=dict)
    rollback_steps: list[dict[str, Any]] = Field(default_factory=list)
    required_confirmation: str = ""
    dry_run: bool = True
    limitations: list[str] = Field(default_factory=list)


class RemediationPreview(BaseModel):
    """Human-readable preview before any mutation."""

    preview_id: str
    endpoint_id: str
    failure_event_id: str
    proposed_action: str
    risk_level: RiskLevel
    rationale: str = ""
    commands_preview: list[str] = Field(default_factory=list)
    rollback_plan: str = ""
    rollback_preview: RollbackPreviewFields | None = None
    requires_typed_confirmation: bool = True
    confirmation_phrase: str = ""
    allowed_by_policy: bool = False
    policy_reason: str = ""
    created_at: str = Field(default_factory=utc_now_iso)


class RemediationExecution(BaseModel):
    """Record of an attempted execution (stdout/stderr redacted)."""

    execution_id: str
    preview_id: str
    endpoint_id: str
    action: str
    confirmed_by: str = "operator_local"
    confirmed_at: str = Field(default_factory=utc_now_iso)
    result: Literal["success", "failure", "blocked", "dry_run"] = "dry_run"
    stdout_redacted: str = ""
    stderr_redacted: str = ""
    rollback_notes: str = ""
    created_at: str = Field(default_factory=utc_now_iso)


class PlatformAuditRecord(BaseModel):
    """Append-only audit row for platform operations."""

    audit_id: str
    actor: str = "operator"
    action: str
    target_type: str = ""
    target_id: str = ""
    decision: str = ""
    rationale: str = ""
    timestamp: str = Field(default_factory=utc_now_iso)

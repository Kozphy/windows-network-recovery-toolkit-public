"""Normalized JSONL envelopes, audit rows, and policy payloads for replay and HTTP APIs.

Module responsibility:
    Declares shared Pydantic models (for example ``NormalizedEvent``, ``AuditEvent``),
    schema-version constants, privacy validators on ``endpoint_id_hash``, and guardrails
    that block overclaimed attribution ``confidence="proof"`` without tamper-evident metadata.

System placement:
    Consumed by ``platform_core.event_bus``, ``platform_core.replay.runner``, demo fixtures,
    and ``backend.platform_routes`` when serializing dashboards.

Timezone assumptions:
    ``timestamp`` fields default through :func:`platform_core.models.utc_now_iso` when callers
    omit them — always UTC-aware ISO strings.

Validation boundaries:
    ``SUPPORTED_SCHEMA_VERSIONS`` gates replay readers; malformed JSON lines remain the
    responsibility of :mod:`platform_core.event_bus`.

Audit Notes:
    Any row that clears proof validators still requires human review—validators catch obvious
    schema abuse, not trusted insider tampering of JSONL files.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from platform_core.models import utc_now_iso

SUPPORTED_SCHEMA_VERSIONS: frozenset[str] = frozenset({"1", "2026.01"})

_ENDPOINT_ID_HASH_RE = re.compile(r"^[a-fA-F0-9]{24,128}$")


def normalize_privacy_endpoint_hash(value: str) -> str:
    """Normalize and validate hashed endpoint identifiers for JSONL ingestion.

    Args:
        value: Operator-supplied correlation token; trailing whitespace tolerated.

    Returns:
        Lowercase hexadecimal string constrained to ``24..128`` characters.

    Raises:
        ValueError: When the candidate is not purely hex within the bounded length band.

    Engineering Notes:
        Length bounds intentionally exceed SHA-256 digests truncated to 32 nibbles while
        keeping obviously human-readable hosts out of telemetry.
    """

    trimmed = value.strip()
    if not _ENDPOINT_ID_HASH_RE.fullmatch(trimmed):
        raise ValueError(
            "endpoint_id_hash must match ^[a-fA-F0-9]{24,128}$ (hashed identifiers only)",
        )
    return trimmed.lower()


PrivacyClass = Literal[
    "internal_operational",
    "diagnostic_general",
    "diagnostic_proxy",
    "manual_only_reference",
]
EventSeverity = Literal["info", "low", "medium", "high", "critical"]
AttributionConfidence = Literal["none", "low", "medium", "high", "proof"]
EventSource = Literal["agent", "cli", "replay", "fixture", "audit", "manual"]


class ActorAttribution(BaseModel):
    """Best-effort attribution; **proof** confidence only when sourced from tamper-evident logs."""

    confidence: AttributionConfidence = "none"
    method: str = "none"
    notes: list[str] = Field(default_factory=list)
    provider: str = "unspecified"
    details: dict[str, Any] = Field(default_factory=dict)


class PolicyDecisionPayload(BaseModel):
    """Serializable gate decision embedded in events (mirrors :class:`StructuredPolicyDecision`)."""

    execute_allowed: bool = False
    preview_allowed: bool = False
    reason_codes: list[str] = Field(default_factory=list)
    required_role: str = "admin"
    required_confirmation: str | None = None
    risk_tier: str = "read_only"


class RemediationPreviewPayload(BaseModel):
    """Optional dry-run summary stored on events (not the full :class:`RemediationPreview`)."""

    proposed_action: str = ""
    rationale: str = ""
    commands_preview_echo: list[str] = Field(default_factory=list)
    rollback_plan_echo: str = ""


def _reject_overclaimed_actor_proof(v: ActorAttribution | None) -> ActorAttribution | None:
    if v is None:
        return v
    if v.confidence == "proof":
        forbidden = {"eventlog_stub", "windows_eventlog_stub", "none", "unspecified", ""}
        if not v.details.get("tamper_evident_source") or v.provider.strip().lower() in forbidden:
            raise ValueError(
                "actor_attribution.confidence proof requires tamper_evident_source in details "
                "and a non-placeholder provider identifier",
            )
    return v


class AuditEvent(BaseModel):
    """Operator or system audit row aligned with JSONL append-only streams."""

    audit_id: str
    schema_version: str = "1"
    event_id: str
    event_type: str = "audit.platform"
    timestamp: str = Field(default_factory=utc_now_iso)
    source: EventSource = "audit"
    severity: EventSeverity = "info"
    endpoint_id_hash: str = Field(description="Truncated stable hash; never raw hostname.")
    summary: str = ""
    actor: str = "operator"
    action: str = ""
    target_ref: str | None = None
    privacy_classification: PrivacyClass = "internal_operational"
    signals: dict[str, Any] = Field(default_factory=dict)
    actor_attribution: ActorAttribution | None = None
    policy_decision: PolicyDecisionPayload | None = None

    @field_validator("endpoint_id_hash")
    @classmethod
    def _endpoint_privacy_audit(cls, v: str) -> str:
        return normalize_privacy_endpoint_hash(v)

    @field_validator("actor_attribution")
    @classmethod
    def _block_false_proof_claims_audit(cls, v: ActorAttribution | None) -> ActorAttribution | None:
        return _reject_overclaimed_actor_proof(v)


class NormalizedEvent(BaseModel):
    """Envelope for correlation, replay, and dashboard surfaces."""

    schema_version: str = "1"
    event_id: str
    event_type: str
    timestamp: str = Field(default_factory=utc_now_iso)
    source: EventSource = "agent"
    severity: EventSeverity = "low"
    endpoint_id_hash: str
    signals: dict[str, Any] = Field(default_factory=dict)
    actor_attribution: ActorAttribution | None = None
    policy_decision: PolicyDecisionPayload | None = None
    remediation_preview: RemediationPreviewPayload | None = None
    privacy_classification: PrivacyClass = "diagnostic_general"

    @field_validator("endpoint_id_hash")
    @classmethod
    def _endpoint_privacy(cls, v: str) -> str:
        return normalize_privacy_endpoint_hash(v)

    @field_validator("actor_attribution")
    @classmethod
    def _block_false_proof_claims(cls, v: ActorAttribution | None) -> ActorAttribution | None:
        return _reject_overclaimed_actor_proof(v)

    def assert_supported_schema(self) -> None:
        """Raise ValueError when schema drift would break replay/dashboard consumers."""

        if self.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported_schema_version:{self.schema_version}")


class SignalDigest(BaseModel):
    """Lightweight deterministic digest used by replay tooling."""

    name: str
    payload: dict[str, Any] = Field(default_factory=dict)

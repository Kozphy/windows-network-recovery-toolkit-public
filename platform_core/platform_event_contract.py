"""Interview-ready canonical event envelopes for the Endpoint Reliability Platform.

Module responsibility:
    Provide typed **envelope** shapes (shared keys + ``payload`` blobs) for docs, dashboards, and tests.
    Routers continue to persist **flat** Pydantic dumps from :mod:`platform_core.models`; this module does not
    replace those serializers—it documents contract vocabulary.

System placement:
    Optional layer above append-only ``platform_data/*.jsonl``. Consumers include demo dashboards,
    pytest contract smoke tests, and narrative diagrams—not mandatory imports for ``backend.platform_routes``.

Key invariants:
    * ``event_type`` literals discriminate semantics; ``payload`` carries variant-specific JSON-safe leaves only.
    * ``endpoint_id=\"*\"`` on :class:`IncidentClusterEvent` denotes multi-endpoint cluster rows—not a real endpoint hash.

Input assumptions:
    Callers supply RFC3339 UTC strings for ``timestamp_utc`` via :func:`~platform_core.models.utc_now_iso`.

Output guarantees:
    ``model_dump()`` yields JSON-serializable dicts suitable for fixtures; no filesystem side effects.

Timezone:
    ``timestamp_utc`` fields MUST be timezone-aware UTC ISO strings.

Schema versioning:
    ``schema_version`` defaults to ``"1"`` — bump deliberately when migrating consumers.

Audit Notes:
    Treat envelopes as **documentation helpers**: accidental reuse of ``payload`` for secrets defeats redaction
    policies upstream—sanitize before embedding operator-provided text.

See Also:
    ``docs/architecture_platform.md`` for diagram context.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from platform_core.models import utc_now_iso


class PlatformEventEnvelope(BaseModel):
    """Minimal envelope shared by distinct platform semantic events.

    Attributes:
        schema_version: Contract revision string—increment when adding breaking payload keys.
        event_id: Correlation identifier (UUID or caller-chosen stable key).
        timestamp_utc: UTC ISO instant when the logical event materialized.
        endpoint_id: Hashed endpoint token or sentinel (see subclasses).
        event_type: Dot-separated category label for dashboards and RBAC presentation.
        payload: Variant-specific JSON object—never substitute for persisted audit rows alone.

    Raises:
        Pydantic validation errors when required fields violate types (FastAPI surfaces as HTTP 422).
    """

    schema_version: str = "1"
    event_id: str
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    endpoint_id: str = ""
    event_type: str = "platform.event"
    payload: dict[str, Any] = Field(default_factory=dict)


class EndpointHeartbeat(PlatformEventEnvelope):
    """Agent or CLI heartbeat — registers liveness without diagnostic payload."""

    event_type: Literal["endpoint.heartbeat"] = "endpoint.heartbeat"
    endpoint_id: str
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Typically os_family, os_version, agent_version mirrors.",
    )


class NetworkStateSnapshot(PlatformEventEnvelope):
    """Privacy-scrubbed network / proxy snapshot row (mirror of EndpointSnapshot semantics)."""

    event_type: Literal["network.snapshot"] = "network.snapshot"
    endpoint_id: str
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="network_state, proxy_state, dns_state, tcp_state blobs — redacted upstream.",
    )


class ProxyDriftEvent(PlatformEventEnvelope):
    """WinINET-aligned drift marker between consecutive polls or diff engines."""

    event_type: Literal["proxy.drift"] = "proxy.drift"
    endpoint_id: str
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="changed_fields, risk_level, parsed_proxy fragments when present.",
    )


class EvidenceEvent(PlatformEventEnvelope):
    """Normalized evidence ingest (Sysmon-shaped row, Procmon CSV excerpt, ETW stub, etc.)."""

    event_type: Literal["evidence.row"] = "evidence.row"
    endpoint_id: str
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="evidence_subtype, attribution_level_hint, sanitized excerpt refs.",
    )


class PlatformAttributionResult(PlatformEventEnvelope):
    """Fused attribution verdict serialized for ``GET /platform/attribution/{event_id}``.

    Note:
        Mirrors :class:`evidence.models.AttributionResult` dict layout inside ``payload`` for strict typing
        helpers while keeping envelope correlation keys top-level.
    """

    event_type: Literal["attribution.result"] = "attribution.result"
    endpoint_id: str = ""
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="candidate_actor, confidence, attribution_level, evidence[], notes.",
    )


class PlatformPolicyDecision(PlatformEventEnvelope):
    """Serialized policy router outcome (distinct from remediation preview rows)."""

    event_type: Literal["policy.decision"] = "policy.decision"
    endpoint_id: str
    payload: dict[str, Any] = Field(
        default_factory=dict,
        description="decision verb, reason_codes[], risk tier, remediation_action key hints.",
    )


class RemediationPreviewEvent(PlatformEventEnvelope):
    """Preview artifact correlation — ``preview_id`` lives in payload or dedicated field."""

    event_type: Literal["remediation.preview"] = "remediation.preview"
    endpoint_id: str
    payload: dict[str, Any] = Field(default_factory=dict)


class RemediationExecutionEvent(PlatformEventEnvelope):
    """Execution outcome envelope mirroring ``RemediationExecution.execution_id``."""

    event_type: Literal["remediation.execution"] = "remediation.execution"
    endpoint_id: str
    payload: dict[str, Any] = Field(default_factory=dict)


class AuditPlatformEvent(PlatformEventEnvelope):
    """Operator/system audit lineage for dashboard explorers."""

    event_type: Literal["audit.platform"] = "audit.platform"
    endpoint_id: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


class IncidentClusterPayload(BaseModel):
    """Summarized cluster emitted by KPI surfaces (distinct UUID from IncidentCluster internals OK)."""

    cluster_id: str
    category: str
    pattern_key: str = ""
    event_ids: list[str] = Field(default_factory=list)
    endpoint_ids: list[str] = Field(default_factory=list)
    first_seen_at: str = ""
    last_seen_at: str = ""
    cluster_severity: str = "low"
    affected_endpoint_count: int = 0
    event_count: int = 0


class IncidentClusterEvent(PlatformEventEnvelope):
    """Cluster snapshot row for timelines / dashboards."""

    event_type: Literal["incident.cluster"] = "incident.cluster"
    endpoint_id: str = "*"  # multi-endpoint sentinel when not singleton-scoped
    payload: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_cluster_payload(cls, c: IncidentClusterPayload) -> IncidentClusterEvent:
        """Materialize a dashboard envelope from deterministic clustering output.

        Args:
            c: Summary row compatible with :mod:`platform_core.incidents` KPI naming.

        Returns:
            :class:`IncidentClusterEvent` whose ``event_id`` mirrors ``cluster_id``.

        Side effects:
            None—constructs in memory only.
        """

        return cls(
            event_id=str(c.cluster_id),
            endpoint_id="*",
            payload=c.model_dump(),
        )

"""Fleet-scale event envelope — stable contract for agents, gateways, and stream consumers."""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from platform_core.models import utc_now_iso
from platform_core.reasoning_models import new_id

StreamKind = Literal[
    "telemetry.normalized",
    "sre.domain",
    "incident.lifecycle",
    "audit.signed",
    "decision.recorded",
]

ProducerKind = Literal["endpoint_agent", "ingest_gateway", "replay_worker", "control_plane"]


class TenantContext(BaseModel):
    """Multi-tenant isolation boundary — every fleet operation carries tenant scope."""

    tenant_id: str = Field(min_length=1, max_length=128)
    org_id: str = ""
    region: str = "default"
    data_residency: str = "default"
    tier: Literal["standard", "enterprise", "regulated"] = "standard"


class IdempotencyRecord(BaseModel):
    """Dedup record for exactly-once ingest semantics at the gateway."""

    tenant_id: str
    producer_id: str
    idempotency_key: str
    event_id: str
    first_seen_utc: str = Field(default_factory=utc_now_iso)
    expires_at_utc: str = ""


class FleetEventEnvelope(BaseModel):
    """Canonical wire format for distributed ingestion and event streaming.

    Idempotency:
        - ``event_id`` is globally unique (UUIDv7-style via ``new_id``).
        - ``idempotency_key`` scopes producer retries (agent batch UUID).
        - Gateway rejects duplicate ``(tenant_id, producer_id, idempotency_key)``.

    Partitioning:
        - ``partition_key`` = f"{tenant_id}:{endpoint_id_hash}".
        - Kafka/Redpanda key = partition_key for ordered per-endpoint delivery.
    """

    schema_version: str = "fleet.envelope.v1"
    event_id: str = Field(default_factory=lambda: new_id("evt"))
    idempotency_key: str = Field(description="Producer-supplied retry key; required for ingest")
    tenant: TenantContext
    producer_id: str = Field(description="Stable agent or gateway instance id")
    producer_kind: ProducerKind = "endpoint_agent"
    endpoint_id_hash: str = Field(min_length=32, max_length=64)
    partition_key: str = ""
    stream: StreamKind = "telemetry.normalized"
    timestamp_utc: str = Field(default_factory=utc_now_iso)
    correlation_id: str = ""
    causation_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_hash: str = ""

    @field_validator("endpoint_id_hash")
    @classmethod
    def _lower_hex_hash(cls, v: str) -> str:
        return v.lower().strip()

    def compute_partition_key(self) -> str:
        """Compute partition key for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return f"{self.tenant.tenant_id}:{self.endpoint_id_hash}"

    def compute_payload_hash(self) -> str:
        """Compute payload hash for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        import json

        blob = json.dumps(self.payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def finalize(self) -> FleetEventEnvelope:
        """Populate derived fields before publish."""
        pk = self.compute_partition_key()
        ph = self.compute_payload_hash()
        return self.model_copy(update={"partition_key": pk, "payload_hash": ph})

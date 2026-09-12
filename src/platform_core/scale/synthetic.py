"""Synthetic endpoint events for local scale testing (not production telemetry)."""

from __future__ import annotations

import hashlib
from typing import Any

from platform_core.fleet.models import FleetEventEnvelope, TenantContext

SYNTHETIC_LIMITATIONS = (
    "Synthetic local scale test — not production telemetry.",
    "Does not prove enterprise fleet scale or malware detection.",
)


def synthetic_endpoint_id(*, index: int, seed: int = 42) -> str:
    """Stable synthetic endpoint id for fixture generation."""
    return f"synthetic-ep-{seed:04d}-{index:06d}"


def synthetic_endpoint_hash(*, index: int, seed: int = 42) -> str:
    """32+ char lowercase hex hash for fleet partition keys."""
    return hashlib.sha256(f"{seed}:endpoint:{index}".encode()).hexdigest()


def synthetic_fleet_envelope(
    *,
    index: int,
    seed: int = 42,
    tenant_id: str = "synthetic-scale",
    producer_id: str = "synthetic-agent",
) -> FleetEventEnvelope:
    """Build one deterministic fleet ingest envelope for scale tests."""
    endpoint_hash = synthetic_endpoint_hash(index=index, seed=seed)
    minute = (index // 60) % 60
    second = index % 60
    return FleetEventEnvelope(
        event_id=f"evt-synth-{seed:04d}-{index:08d}",
        idempotency_key=f"synth-{seed:04d}-{index:08d}",
        tenant=TenantContext(tenant_id=tenant_id),
        producer_id=producer_id,
        endpoint_id_hash=endpoint_hash,
        timestamp_utc=f"2026-06-12T08:{minute:02d}:{second:02d}Z",
        payload={
            "event_kind": "synthetic_endpoint_evidence",
            "endpoint_id": synthetic_endpoint_id(index=index, seed=seed),
            "signal_name": "wininet_proxy_enabled",
            "synthetic": True,
            "scale_test_seed": seed,
            "index": index,
            "limitations": list(SYNTHETIC_LIMITATIONS),
        },
    ).finalize()


def synthetic_spool_event(
    *,
    index: int,
    seed: int = 42,
    trace_id: str | None = None,
    audit_id: str | None = None,
) -> dict[str, Any]:
    """Build one read-only agent-style spool row for concurrency tests."""
    endpoint_id = synthetic_endpoint_id(index=index, seed=seed)
    row: dict[str, Any] = {
        "event_kind": "agent_evidence_collected",
        "endpoint_id": endpoint_id,
        "read_only": True,
        "automatic_repair": False,
        "remediation_executed": False,
        "policy_boundary": "read_only_no_mutation",
        "synthetic": True,
        "scale_test_seed": seed,
        "index": index,
        "limitations": list(SYNTHETIC_LIMITATIONS),
        "evidence": {
            "os_family": "windows",
            "platform_support_level": "FULL",
            "observations": [{"signal_name": "synthetic", "value": index, "source": "scale_test"}],
        },
    }
    if trace_id:
        row["trace_id"] = trace_id
    if audit_id:
        row["audit_id"] = audit_id
    return row


def ingest_synthetic_batch(
    gateway: Any,
    *,
    count: int,
    seed: int = 42,
    tenant_id: str = "synthetic-scale",
) -> dict[str, Any]:
    """Ingest ``count`` unique synthetic envelopes; return summary stats."""
    accepted = 0
    duplicates = 0
    conflicts = 0
    for index in range(count):
        envelope = synthetic_fleet_envelope(index=index, seed=seed, tenant_id=tenant_id)
        result = gateway.ingest_one(envelope)
        if result.dedup.outcome == "accepted":
            accepted += 1
        elif result.dedup.outcome == "duplicate":
            duplicates += 1
        elif result.dedup.outcome == "conflict":
            conflicts += 1
    return {
        "count": count,
        "seed": seed,
        "accepted": accepted,
        "duplicates": duplicates,
        "conflicts": conflicts,
        "synthetic": True,
        "limitations": list(SYNTHETIC_LIMITATIONS),
    }

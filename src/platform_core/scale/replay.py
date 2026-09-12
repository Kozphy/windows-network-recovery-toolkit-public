"""Deterministic replay verification for synthetic ingest WAL (local scale tests)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from platform_core.fleet.models import FleetEventEnvelope
from platform_core.fleet.partitioning import assign_partition
from platform_core.storage import iter_jsonl


def load_ingest_wal(wal_path: Path) -> list[dict[str, Any]]:
    """Load fleet ingest WAL rows (skips corrupt lines)."""
    return list(iter_jsonl(wal_path))


def project_envelope_partitions(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deterministic partition projection sorted by ``event_id``."""
    projections: list[dict[str, Any]] = []
    for raw in sorted(records, key=lambda row: str(row.get("event_id", ""))):
        envelope = FleetEventEnvelope.model_validate(raw)
        part = assign_partition(envelope.tenant.tenant_id, envelope.endpoint_id_hash)
        projections.append(
            {
                "event_id": envelope.event_id,
                "partition_id": part.partition_id,
                "endpoint_id_hash": envelope.endpoint_id_hash,
                "payload_hash": envelope.payload_hash,
            }
        )
    return projections


def projection_digest(projections: list[dict[str, Any]]) -> str:
    """SHA-256 digest of canonical partition projection (replay fingerprint)."""
    canonical = json.dumps(projections, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def deterministic_replay_from_wal(wal_path: Path) -> dict[str, Any]:
    """Replay ingest WAL into a stable partition projection (read-only)."""
    records = load_ingest_wal(wal_path)
    projections = project_envelope_partitions(records)
    return {
        "record_count": len(records),
        "projection_digest": projection_digest(projections),
        "synthetic": True,
    }


def verify_deterministic_replay(wal_path: Path) -> tuple[bool, str]:
    """Run replay twice; digests must match (idempotent local replay)."""
    first = deterministic_replay_from_wal(wal_path)
    second = deterministic_replay_from_wal(wal_path)
    if first["projection_digest"] != second["projection_digest"]:
        return False, "replay digest mismatch between runs"
    if first["record_count"] != second["record_count"]:
        return False, "record count mismatch between replay runs"
    return True, first["projection_digest"]

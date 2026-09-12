"""Synthetic local scale testing helpers (not production fleet benchmarks)."""

from src.platform_core.scale.replay import (
    deterministic_replay_from_wal,
    load_ingest_wal,
    project_envelope_partitions,
    projection_digest,
    verify_deterministic_replay,
)
from src.platform_core.scale.synthetic import (
    SYNTHETIC_LIMITATIONS,
    ingest_synthetic_batch,
    synthetic_endpoint_hash,
    synthetic_endpoint_id,
    synthetic_fleet_envelope,
    synthetic_spool_event,
)

__all__ = [
    "SYNTHETIC_LIMITATIONS",
    "deterministic_replay_from_wal",
    "ingest_synthetic_batch",
    "load_ingest_wal",
    "projection_digest",
    "project_envelope_partitions",
    "synthetic_endpoint_hash",
    "synthetic_endpoint_id",
    "synthetic_fleet_envelope",
    "synthetic_spool_event",
    "verify_deterministic_replay",
]

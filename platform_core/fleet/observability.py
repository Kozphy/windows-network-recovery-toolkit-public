"""Fleet-scale observability labels and SLO metric names."""

from __future__ import annotations

from typing import Any

FLEET_METRIC_NAMES = (
    "fleet_ingest_accepted_total",
    "fleet_ingest_duplicate_total",
    "fleet_ingest_conflict_total",
    "fleet_ingest_publish_lag_seconds",
    "fleet_partition_lag_seconds",
    "fleet_replay_job_duration_seconds",
    "fleet_replay_parity_failure_total",
    "fleet_tenant_ingest_rps",
    "fleet_dedup_store_latency_seconds",
)


def ingest_result_to_labels(tenant_id: str, partition_id: int, outcome: str) -> dict[str, str]:
    """Ingest result to labels for toolkit workflows.

    Args:
        tenant_id: Value supplied by the caller for tenant id.
        partition_id: Value supplied by the caller for partition id.
        outcome: Value supplied by the caller for outcome.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    return {
        "tenant_id": tenant_id[:32],
        "partition": str(partition_id),
        "outcome": outcome,
    }


def fleet_metrics_documentation() -> dict[str, str]:
    """Provide fleet metrics documentation behavior for toolkit workflows.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return {
        "fleet_ingest_accepted_total": "Events accepted by ingest gateway after dedup (per tenant/partition).",
        "fleet_ingest_duplicate_total": "Idempotent retries — same idempotency_key and event_id.",
        "fleet_ingest_conflict_total": "Rejected — idempotency_key reuse with different payload.",
        "fleet_ingest_publish_lag_seconds": "Time from agent timestamp to stream publish.",
        "fleet_partition_lag_seconds": "Consumer lag per partition — alert > 300s.",
        "fleet_replay_job_duration_seconds": "Partition replay job wall time.",
        "fleet_replay_parity_failure_total": "Replay parity mismatch (policy/state/hypothesis).",
        "fleet_tenant_ingest_rps": "Per-tenant ingest rate for noisy-neighbor detection.",
        "fleet_dedup_store_latency_seconds": "Idempotency store check_and_record latency.",
    }


def merge_fleet_into_platform_metrics(
    base: dict[str, Any], *, ingest_stats: dict[str, int] | None = None
) -> dict[str, Any]:
    """Merge fleet into platform metrics for toolkit workflows.

    Args:
        base: Value supplied by the caller for base.
        ingest_stats: Value supplied by the caller for ingest stats.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    stats = ingest_stats or {}
    base["fleet_metrics"] = {
        "ingest_accepted": stats.get("accepted", 0),
        "ingest_duplicate": stats.get("duplicate", 0),
        "ingest_conflict": stats.get("conflict", 0),
    }
    return base

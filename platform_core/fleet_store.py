"""JSONL-backed fleet store for endpoint heartbeats (local-first, no database)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from platform_core.endpoint_model import EndpointRecord, RiskState
from platform_core.storage import _path, append_jsonl, iter_jsonl


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    text = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _coerce_risk_state(value: Any) -> RiskState:
    raw = str(value or "unknown").lower()
    if raw in ("healthy", "degraded", "incident_open", "unknown"):
        return raw  # type: ignore[return-value]
    return "unknown"


def record_from_row(row: dict[str, Any]) -> EndpointRecord:
    """Record from row for toolkit workflows.

    Args:
        row: Value supplied by the caller for row.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    return EndpointRecord(
        endpoint_id=str(row.get("endpoint_id") or ""),
        hostname=str(row.get("hostname") or row.get("hostname_hash") or ""),
        os_name=str(row.get("os_name") or row.get("os_family") or ""),
        agent_version=str(row.get("agent_version") or ""),
        first_seen=str(
            row.get("first_seen") or row.get("first_seen_at") or row.get("last_seen_at") or ""
        ),
        last_seen=str(row.get("last_seen") or row.get("last_seen_at") or ""),
        latest_snapshot_id=str(row.get("latest_snapshot_id") or row.get("snapshot_id") or ""),
        latest_diagnosis_id=str(row.get("latest_diagnosis_id") or row.get("diagnosis_id") or ""),
        risk_state=_coerce_risk_state(row.get("risk_state") or row.get("status")),
    )


def append_heartbeat(row: dict[str, Any], *, store_path: Path | None = None) -> EndpointRecord:
    """Append one heartbeat row and return merged endpoint state."""
    path = store_path or _path("fleet_endpoints.jsonl")
    eid = str(row.get("endpoint_id") or "")
    if not eid:
        raise ValueError("endpoint_id required for heartbeat")

    existing = get_endpoint(eid, store_path=path)
    merged = {
        **(existing.to_summary_row() if existing else {}),
        **row,
        "endpoint_id": eid,
        "first_seen": (
            existing.first_seen if existing else row.get("first_seen") or row.get("last_seen_at")
        ),
        "last_seen": row.get("last_seen") or row.get("last_seen_at") or row.get("timestamp"),
    }
    if not merged.get("first_seen"):
        merged["first_seen"] = merged.get("last_seen") or datetime.now(UTC).isoformat()
    append_jsonl(path, merged)
    return record_from_row(merged)


def get_endpoint(endpoint_id: str, *, store_path: Path | None = None) -> EndpointRecord | None:
    """Get endpoint for toolkit workflows.

    Args:
        endpoint_id: Value supplied by the caller for endpoint id.
        store_path: Value supplied by the caller for store path.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    path = store_path or _path("fleet_endpoints.jsonl")
    latest: dict[str, Any] | None = None
    for row in iter_jsonl(path):
        if str(row.get("endpoint_id") or "") == endpoint_id:
            latest = row
    return record_from_row(latest) if latest else None


def list_endpoints(*, store_path: Path | None = None) -> list[EndpointRecord]:
    """List endpoints for toolkit workflows.

    Args:
        store_path: Value supplied by the caller for store path.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    path = store_path or _path("fleet_endpoints.jsonl")
    by_id: dict[str, dict[str, Any]] = {}
    for row in iter_jsonl(path):
        eid = str(row.get("endpoint_id") or "")
        if eid:
            by_id[eid] = row
    return [record_from_row(row) for row in by_id.values()]


def apply_stale_policy(
    records: list[EndpointRecord],
    *,
    stale_after_seconds: int = 86400,
    now: datetime | None = None,
) -> list[EndpointRecord]:
    """Mark endpoints not seen within threshold as unknown."""
    clock = now or datetime.now(UTC)
    updated: list[EndpointRecord] = []
    for record in records:
        last = _parse_iso(record.last_seen)
        if last is None:
            updated.append(record.model_copy(update={"risk_state": "unknown"}))
            continue
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if (
            clock - last
        ).total_seconds() > stale_after_seconds and record.risk_state != "incident_open":
            updated.append(record.model_copy(update={"risk_state": "unknown"}))
        else:
            updated.append(record)
    return updated

"""Append-only JSONL incident store."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from platform_core.incident_model import IncidentRecord, IncidentState
from platform_core.models import utc_now_iso
from platform_core.storage import _path, append_jsonl, iter_jsonl


def append_incident_event(row: dict[str, Any], *, store_path: Path | None = None) -> None:
    """Append incident event for toolkit workflows.

    Args:
        row: Value supplied by the caller for row.
        store_path: Value supplied by the caller for store path.

    Returns:
        None.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    path = store_path or _path("incidents.jsonl")
    append_jsonl(path, row)


def list_incident_rows(*, store_path: Path | None = None) -> list[dict[str, Any]]:
    """List incident rows for toolkit workflows.

    Args:
        store_path: Value supplied by the caller for store path.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    path = store_path or _path("incidents.jsonl")
    latest: dict[str, dict[str, Any]] = {}
    for row in iter_jsonl(path):
        iid = str(row.get("incident_id") or "")
        if iid:
            latest[iid] = row
    return sorted(latest.values(), key=lambda r: str(r.get("updated_at") or ""))


def get_incident(incident_id: str, *, store_path: Path | None = None) -> dict[str, Any] | None:
    """Get incident for toolkit workflows.

    Args:
        incident_id: Value supplied by the caller for incident id.
        store_path: Value supplied by the caller for store path.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    path = store_path or _path("incidents.jsonl")
    latest: dict[str, Any] | None = None
    for row in iter_jsonl(path):
        if str(row.get("incident_id") or "") == incident_id:
            latest = row
    return latest


def transition_incident(
    incident_id: str,
    *,
    new_state: IncidentState,
    actor: str = "platform_api",
    store_path: Path | None = None,
) -> IncidentRecord:
    """Transition incident for toolkit workflows.

    Args:
        incident_id: Value supplied by the caller for incident id.
        new_state: Value supplied by the caller for new state.
        actor: Value supplied by the caller for actor.
        store_path: Value supplied by the caller for store path.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    current = get_incident(incident_id, store_path=store_path)
    if not current:
        raise KeyError(f"incident not found: {incident_id}")
    record = IncidentRecord.model_validate(current)
    row = record.model_dump(mode="json")
    row["state"] = new_state
    row["updated_at"] = utc_now_iso()
    row["last_transition_actor"] = actor
    append_incident_event(row, store_path=store_path)
    return IncidentRecord.model_validate(row)

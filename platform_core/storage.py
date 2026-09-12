"""Append-only JSONL persistence for the Endpoint Reliability Platform prototype.

Module responsibility:
    Owns file layout under ``platform_data/`` (or ``PLATFORM_DATA_DIR``): endpoints, snapshots,
    failure events, remediation previews/executions, and audit rows—each as a dedicated ``*.jsonl``
    stream consumed by ``backend/platform_routes.py`` and emitted by ``endpoint_agent``.

System placement:
    Sits **below** Pydantic models and **above** the filesystem; ``platform_core.policy`` never
    writes here directly—routers and the agent call these helpers.

Key invariants:
    * Records are newline-delimited UTF-8 JSON; no transactions—readers use
      :func:`iter_jsonl` which **skips** corrupt lines.
    * ``find_by_id`` returns the **latest** match scanning from oldest to newest (portfolio
      scale assumption).

Input assumptions:
    Callers pass ``dict[str, Any]`` payloads already validated or produced from
    ``model_dump(mode="json")``; this module does not strip secrets.

Output guarantees:
    Iterators yield only ``dict`` instances successfully parsed from JSON; empty/malformed lines are
    ignored.

Side effects:
    Every ``append_*`` helper may create parent directories and append to files.

Idempotency:
    Appends are **not** duplicate-safe—idempotency belongs to higher layers (for example dry-run
    keys in execution records).

Failure modes:
    Disk full, permission denied, or antivirus locks manifest as ``OSError`` bubbling to FastAPI as
    HTTP 500 unless caught by routers.

Audit Notes:
    Compare ``audit.jsonl`` timestamps with remediation execution rows when investigating “who
    approved this script.” ``list_metrics`` performs full scans—acceptable for demos, not for very
    large files without rotation.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .models import utc_now_iso

DEFAULT_REL_PLATFORM_DATA = Path(__file__).resolve().parent.parent / "platform_data"


def platform_data_dir() -> Path:
    """Resolve the JSONL root directory.

    Returns:
        Absolute path from environment variable ``PLATFORM_DATA_DIR`` when set, else
        ``<repo>/platform_data`` relative to this package's parent directory.

    Side effects:
        None.
    """
    raw = os.environ.get("PLATFORM_DATA_DIR")
    if raw:
        return Path(raw).resolve()
    return DEFAULT_REL_PLATFORM_DATA


def _path(name: str) -> Path:
    return platform_data_dir() / name


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    """Append one JSON object as a single UTF-8 line (advisory file lock when available).

    Args:
        path: Destination file; parent directories are created as needed.
        record: JSON-serializable mapping (``default=str`` for non-JSON-native values).

    Raises:
        ``OSError`` if the path is not writable.

    Side effects:
        Creates ``path.parent`` and appends one line under a per-file advisory lock when
        :mod:`src.platform_core.io.locked_jsonl` is importable.
    """
    try:
        from src.platform_core.io.locked_jsonl import append_jsonl_locked

        append_jsonl_locked(path, record)
        return
    except ImportError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, default=str)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Yield parsed ``dict`` rows in file order, tolerating blank or invalid JSON lines.

    Malformed lines are dropped (typical after abrupt shutdown or concurrent writers). Missing
    files produce zero yields.
    """
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def read_recent_jsonl(path: Path, limit: int = 100) -> list[dict[str, Any]]:
    """Return up to ``limit`` trailing records after a full-file read (O(n) in line count).

    Engineering Notes:
        Suited for dashboard demos; replace with tail-indexed storage if files grow large.
    """
    rows = list(iter_jsonl(path))
    if limit >= len(rows):
        return rows
    return rows[-limit:]


def find_by_id(path: Path, id_field: str, id_value: str) -> dict[str, Any] | None:
    """Scan JSONL and return the **last** row whose ``id_field`` equals ``id_value``."""
    last: dict[str, Any] | None = None
    for obj in iter_jsonl(path):
        if obj.get(id_field) == id_value:
            last = obj
    return last


def upsert_endpoint(record: dict[str, Any]) -> None:
    """Append a heartbeat row; logical ``upsert`` is **latest append wins** per reader conventions."""
    append_jsonl(_path("endpoints.jsonl"), record)


def record_audit(record: dict[str, Any]) -> None:
    """Append an audit dict, injecting ``audit_id`` / ``timestamp`` into ``record`` when absent.

    Side effects:
        Mutates ``record`` in place for missing keys before appending to ``audit.jsonl``.
    """
    if "audit_id" not in record:
        record["audit_id"] = str(uuid.uuid4())
    if "timestamp" not in record:
        record["timestamp"] = utc_now_iso()
    append_jsonl(_path("audit.jsonl"), record)


def append_snapshot(record: dict[str, Any]) -> None:
    """Append one :class:`~platform_core.models.EndpointSnapshot` dump to ``snapshots.jsonl``."""
    append_jsonl(_path("snapshots.jsonl"), record)


def append_failure_event(record: dict[str, Any]) -> None:
    """Append one serialized :class:`~platform_core.models.FailureEvent` row."""
    append_jsonl(_path("failure_events.jsonl"), record)


def append_remediation_preview(record: dict[str, Any]) -> None:
    """Persist a deterministic preview record before any live execution attempt."""
    append_jsonl(_path("remediation_previews.jsonl"), record)


def append_remediation_execution(record: dict[str, Any]) -> None:
    """Record dry-run or live script outcomes for success-rate style metrics."""
    append_jsonl(_path("remediation_executions.jsonl"), record)


def append_platform_signal(record: dict[str, Any]) -> None:
    """Append a KPI / telemetry signal row for :mod:`platform_core.metrics` rollups.

    Args:
        record: Loose JSON mapping; tolerant ``kind``/``signal`` keys drive bucket increments.

    Schema (illustrative, tolerant):
        * ``kind`` — ``proxy_registry_change`` | ``proxy_enable_transition`` | ``heartbeat`` |
          ``rollback_preview`` | ``rollback_execute`` | ``rollback_blocked`` |
          ``attribution_sample`` | ``unknown_actor_marker``
        * Optional numeric fields such as ``confidence`` for attribution averages.

    Side effects:
        Creates ``platform_signals.jsonl`` implicitly via append path helper.

    Idempotency:
        Every call emits a new physical line — dedupe absent by design.

    Audit Notes:
        Validate suspicious spikes by tailing JSONL—not metrics alone—in case rogue agents spam identical kinds.
    """

    append_jsonl(_path("platform_signals.jsonl"), record)


def append_attribution_record(record: dict[str, Any]) -> None:
    """Persist immutable attribution payloads emitted by backend GET flows.

    Args:
        record: Typically :meth:`evidence.models.AttributionResult.as_dict` output including ``event_id``.

    Raises:
        ``OSError`` from append helper when storage path not writable.

    Audit Notes:
        Historical rows coexist—readers scanning for latest match must mimic ``find_latest_attribution``.
    """

    append_jsonl(_path("attribution_records.jsonl"), record)


def find_latest_attribution(event_id: str) -> dict[str, Any] | None:
    """Return the newest attribution row for ``event_id`` if present.

    Args:
        event_id: Correlates with ``failure_events.jsonl``.

    Returns:
        Last chronological dict match or ``None`` when absent.

    Complexity:
        O(n) streaming read—portfolio acceptable; large files need indexing externally.

    Stale handling:
        Duplicate IDs append verbatim; last encountered row wins semantics.

    Raises:
        None—parse errors swallowed by :func:`iter_jsonl`.
    """

    last: dict[str, Any] | None = None
    for obj in iter_jsonl(_path("attribution_records.jsonl")):
        if obj.get("event_id") == event_id:
            last = obj
    return last


def append_attribution_context(record: dict[str, Any]) -> None:
    """Stage Sysmon/Procmon/registry hints keyed by ``event_id`` for ``GET /platform/attribution``.

    Args:
        record: Fixture dict minimally containing matching ``event_id`` plus telemetry arrays.

    Side effects:
        Always appends—even partial fixtures—to preserve audit trail ordering.

    Engineering Notes:
        Tests supply synthetic contexts; operators should treat file as confidential derived evidence comparable to Tier-2 logs.

    Raises:
        ``OSError`` if JSONL destination cannot append.
    """

    append_jsonl(_path("attribution_context.jsonl"), record)


def find_attribution_context(event_id: str) -> dict[str, Any] | None:
    """Return optional evidence bundle pre-staged for an event.

    Duplicate ``event_id`` rows yield last-write chronology identical to attribution storage conventions.

    Returns:
        Dict context or ``None`` when unstaged—HTTP layer recomputes heuristics absent rows.

    Failure modes:
        Malformed trailing JSON lines silently dropped per iterator policy.

    Raises:
        None.
    """

    last: dict[str, Any] | None = None
    for obj in iter_jsonl(_path("attribution_context.jsonl")):
        if obj.get("event_id") == event_id:
            last = obj
    return last


def list_metrics() -> dict[str, Any]:
    """Aggregate counters and rates from JSONL streams for ``GET /platform/metrics``.

    Returns:
        Plain dict with endpoint counts, open events, cluster aggregates, execution stats, and
        optional rates (``None`` when denominators vanish).

    Side effects:
        Reads multiple JSONL files fully—fine for demos; streaming metrics would require a different
        storage layout.

    Failure modes:
        Corrupt lines are skipped by :func:`iter_jsonl`. Unexpected field shapes skew counts silently
        (for example strings where integers are assumed).
    """

    from .incidents import cluster_failure_events

    fe_path = _path("failure_events.jsonl")
    endpoints_path = _path("endpoints.jsonl")
    prev_path = _path("remediation_previews.jsonl")
    exec_path = _path("remediation_executions.jsonl")
    audit_path = _path("audit.jsonl")

    events = list(iter_jsonl(fe_path))
    open_events = sum(1 for e in events if e.get("status") == "open")
    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    for e in events:
        c = str(e.get("category") or "unknown")
        by_cat[c] = by_cat.get(c, 0) + 1
        s = str(e.get("severity") or "low")
        by_sev[s] = by_sev.get(s, 0) + 1

    endpoint_ids = {
        e.get("endpoint_id") for e in iter_jsonl(endpoints_path) if e.get("endpoint_id")
    }

    blocked = sum(1 for a in iter_jsonl(audit_path) if a.get("decision") == "blocked")

    clusters = cluster_failure_events(events, window_seconds=7200)
    affected_eps: set[str] = set()
    for cl in clusters:
        affected_eps.update(cl.endpoint_ids)

    exec_rows = list(iter_jsonl(exec_path))
    dry_run_count = sum(1 for x in exec_rows if x.get("result") == "dry_run")
    success_count = sum(1 for x in exec_rows if x.get("result") == "success")
    failure_count = sum(1 for x in exec_rows if x.get("result") == "failure")
    outcome_denom = success_count + failure_count
    repair_success_rate: float | None = (
        round(success_count / outcome_denom, 4) if outcome_denom else None
    )

    fp_count = sum(1 for e in events if e.get("status") == "false_positive")
    false_positive_rate: float | None = round(fp_count / len(events), 4) if events else None

    return {
        "endpoint_count": len(endpoint_ids),
        "open_failure_events": open_events,
        "events_by_category": by_cat,
        "events_by_severity": by_sev,
        "incident_cluster_count": len(clusters),
        "affected_endpoint_count": len(affected_eps),
        "remediation_preview_count": sum(1 for _ in iter_jsonl(prev_path)),
        "remediation_execution_count": len(exec_rows),
        "blocked_action_count": blocked,
        "dry_run_execution_count": dry_run_count,
        "repair_success_rate": repair_success_rate,
        "false_positive_rate": false_positive_rate,
    }

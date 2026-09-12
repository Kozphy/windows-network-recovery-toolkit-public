"""Merge append-only telemetry into dashboard-friendly counters.

Module responsibility:
    Extend legacy :func:`~platform_core.storage.list_metrics` rollups with ``platform_signals.jsonl``
    KPI vocabulary (proxy drift, rollback storytelling, attribution confidence sampling).

System placement:
    Consumed exclusively by FastAPI ``GET /platform/metrics`` via :func:`compute_platform_metrics`
    (:mod:`backend.platform_routes`).

Input assumptions:
    JSONL shards live under configurable ``PLATFORM_DATA_DIR`` roots; malformed lines skipped silently by
    :func:`~platform_core.storage.iter_jsonl`.

Output guarantees:
    Deterministic dict merge for identical on-disk corpus ordering—cluster recomputation aligns ``incident_cluster_count`` with rebuilt incident helper even when legacy aggregator embedded divergent summaries.

Timezone:
    Signals themselves carry whatever timestamp strings producers appended—this module aggregates counts only without parsing clock fields aside from attribution confidence floats.

Duplicates:
    Repeated identical signal rows inflate totals intentionally (signals are events, not state snapshots).

Engineering Notes:
    Full-table scans suffice for demos; fleet-scale installs would migrate to incremental counters.

Audit Notes:
    Cross-check unexplained KPI spikes vs concurrent agents writing conflicting ``platform_signals`` streams—locking absent by design here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from platform_core.incidents import cluster_failure_events
from platform_core.storage import iter_jsonl, list_metrics, platform_data_dir


def _signals_path(root: Path | None) -> Path:
    """Return absolute Path to ``platform_signals.jsonl`` scoped to optional override root."""

    base = root if root is not None else platform_data_dir()
    return base / "platform_signals.jsonl"


def _rollup_signals(path: Path) -> dict[str, Any]:
    """Normalize ``platform_signals.jsonl`` into raw counter buckets plus attribution sample list."""

    proxy_changes_total = 0
    proxy_enable_transitions_total = 0
    unknown_actor_events_total = 0
    rollback_preview_total = 0
    rollback_execute_total = 0
    rollback_blocked_total = 0
    endpoint_heartbeat_total = 0
    attribution_confidences: list[float] = []

    if not path.is_file():
        return {
            "proxy_changes_total": 0,
            "proxy_enable_transitions_total": 0,
            "unknown_actor_events_total": 0,
            "rollback_preview_total": 0,
            "rollback_execute_total": 0,
            "rollback_blocked_total": 0,
            "endpoint_heartbeat_total": 0,
            "attribution_confidence_samples": [],
        }

    for row in iter_jsonl(path):
        kind = str(row.get("kind") or row.get("signal") or "")
        if kind in ("proxy_registry_change", "proxy_change"):
            proxy_changes_total += 1
        elif kind == "proxy_enable_transition":
            proxy_enable_transitions_total += 1
        elif kind == "heartbeat":
            endpoint_heartbeat_total += 1
        elif kind == "rollback_preview":
            rollback_preview_total += 1
        elif kind == "rollback_execute":
            rollback_execute_total += 1
        elif kind == "rollback_blocked":
            rollback_blocked_total += 1
        elif kind == "unknown_actor_marker":
            unknown_actor_events_total += 1
        else:
            uk = row.get("unknown_actor")
            if uk is True or str(uk).lower() in ("1", "true", "yes"):
                unknown_actor_events_total += 1

        if "confidence" in row and isinstance(row.get("confidence"), (int, float)):
            attribution_confidences.append(float(row["confidence"]))
        elif kind == "attribution_sample" and isinstance(row.get("score"), (int, float)):
            attribution_confidences.append(float(row["score"]))

    # merge attribution_records.jsonl for avg confidence alongside signals
    return {
        "proxy_changes_total": proxy_changes_total,
        "proxy_enable_transitions_total": proxy_enable_transitions_total,
        "unknown_actor_events_total": unknown_actor_events_total,
        "rollback_preview_total": rollback_preview_total,
        "rollback_execute_total": rollback_execute_total,
        "rollback_blocked_total": rollback_blocked_total,
        "endpoint_heartbeat_total": endpoint_heartbeat_total,
        "attribution_confidence_samples": attribution_confidences,
    }


def _attribution_file_confidences(root: Path) -> list[float]:
    """Harvest numeric confidence fields persisted by attribution persistence layer."""

    path = root / "attribution_records.jsonl"
    out: list[float] = []
    if not path.is_file():
        return out
    for row in iter_jsonl(path):
        c = row.get("confidence")
        if isinstance(c, (int, float)):
            out.append(float(c))
    return out


def compute_platform_metrics(*, platform_root: Path | None = None) -> dict[str, Any]:
    """Produce superset KPI mapping for dashboards and pytest fixtures.

    Args:
        platform_root: Optional filesystem root honoring tests monkeypatching ``platform_data``; defaults
            to ``platform_data_dir()`` when ``None``.

    Returns:
        Dict combining legacy rollup keys, KPI counters, attribution averages, deterministic cluster metrics,
        and informational ``signals_file`` path echo.

    Side effects:
        Read-only traversal of JSONL shards.

    Constraints:
        When ``platform_root`` is supplied, legacy metrics recompute via :func:`_list_metrics_shim` to honour
        isolated directories; otherwise forwards to live :func:`~platform_core.storage.list_metrics`.

    Raises:
        ``OSError`` only if iterators cannot open files—rare inside controlled tests.

    Audit Notes:
        Investigate divergence between embedded ``repair_success_rate`` and external observability tooling by
        diffing underlying ``remediation_executions.jsonl`` rows—not this function’s summarized view alone.
    """

    root = platform_root if platform_root is not None else platform_data_dir()
    legacy = dict(list_metrics() if platform_root is None else _list_metrics_shim(root))

    sig = _rollup_signals(root / "platform_signals.jsonl")
    att_samples = list(sig.pop("attribution_confidence_samples", []))
    att_samples.extend(_attribution_file_confidences(root))

    attribution_confidence_avg: float | None = None
    if att_samples:
        attribution_confidence_avg = round(sum(att_samples) / len(att_samples), 6)

    # enrich cluster stats directly from failure_events for deterministic naming aligned to spec labels
    fe_path = root / "failure_events.jsonl"
    events = list(iter_jsonl(fe_path))
    clusters = cluster_failure_events(events, window_seconds=7200)
    affected_eps: set[str] = set()
    for cl in clusters:
        affected_eps.update(cl.endpoint_ids)

    merged: dict[str, Any] = {
        **legacy,
        # required portfolio names
        "proxy_changes_total": sig["proxy_changes_total"],
        "proxy_enable_transitions_total": sig["proxy_enable_transitions_total"],
        "unknown_actor_events_total": sig["unknown_actor_events_total"],
        "attribution_confidence_avg": attribution_confidence_avg,
        "rollback_preview_total": sig["rollback_preview_total"],
        "rollback_execute_total": sig["rollback_execute_total"],
        "rollback_blocked_total": sig["rollback_blocked_total"],
        "endpoint_heartbeat_total": sig["endpoint_heartbeat_total"],
        "incident_cluster_count": len(clusters),
        "affected_endpoint_count": len(affected_eps),
    }
    merged["signals_file"] = str(root / "platform_signals.jsonl")
    audit_path = root / "audit.jsonl"
    merged["audit_row_count"] = sum(1 for _ in iter_jsonl(audit_path))
    from platform_core.reliability_metrics import reliability_metrics_dict

    merged["reliability_metrics"] = reliability_metrics_dict(data_root=root)
    from platform_core.reliability_metrics import slo_metrics_dict

    merged["slo_metrics"] = slo_metrics_dict(data_root=root)
    try:
        from platform_core.sre.mttr import (
            compute_incident_mttr_metrics,
            mttr_metrics_for_prometheus,
        )

        sre_metrics = compute_incident_mttr_metrics()
        merged["sre_incident_metrics"] = sre_metrics.model_dump(mode="json")
        merged["sre_mttr_metrics"] = mttr_metrics_for_prometheus(sre_metrics)
    except Exception:
        merged["sre_incident_metrics"] = {}
        merged["sre_mttr_metrics"] = {}
    return merged


def _list_metrics_shim(platform_root: Path) -> dict[str, Any]:
    """Mirror :func:`~platform_core.storage.list_metrics` math against arbitrary ``platform_root``.

    Purpose:
        Keep pytest isolation without mutating module-level path resolution semantics.

    Args:
        platform_root: Writable/readable temp directory substituted during tests.

    Returns:
        Identical statistical schema emitted by legacy ``list_metrics`` for stable assertions.

    Engineering Notes:
        Duplicates logic intentionally to avoid import cycles or mutating globals mid-request.
    """

    from platform_core.incidents import cluster_failure_events as _cluster

    fe_path = platform_root / "failure_events.jsonl"
    endpoints_path = platform_root / "endpoints.jsonl"
    prev_path = platform_root / "remediation_previews.jsonl"
    exec_path = platform_root / "remediation_executions.jsonl"
    audit_path = platform_root / "audit.jsonl"

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
    clusters = _cluster(events, window_seconds=7200)
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

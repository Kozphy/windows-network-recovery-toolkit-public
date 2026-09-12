"""Prometheus gauges for endpoint reliability JSONL streams."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from platform_core.storage import iter_jsonl, platform_data_dir


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    text = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def compute_endpoint_prometheus_gauges(*, data_root: Path | None = None) -> dict[str, float]:
    """Compute endpoint prometheus gauges for toolkit workflows.

    Args:
        data_root: Value supplied by the caller for data root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    root = data_root if data_root is not None else platform_data_dir()
    out: dict[str, float] = defaultdict(float)
    diagnosis_deltas: list[float] = []

    for row in iter_jsonl(root / "platform_signals.jsonl"):
        out["endpoint_events_total"] += 1.0
        kind = str(row.get("kind") or row.get("signal") or "")
        if kind in ("proxy_registry_change", "proxy_change", "proxy_enable_transition"):
            out["proxy_drift_incidents_total"] += 1.0
        occurred = _parse_iso(row.get("occurred_at"))
        detected = _parse_iso(row.get("detected_at"))
        if occurred and detected:
            diagnosis_deltas.append(max(0.0, (detected - occurred).total_seconds()))

    for row in iter_jsonl(root / "failure_events.jsonl"):
        sev = str(row.get("severity") or "unknown").lower()
        out[f"incidents_by_severity_total_{sev}"] += 1.0
        lvl = str(row.get("evidence_level") or row.get("proof_status") or "unknown").lower()
        out[f"evidence_level_total_{lvl}"] += 1.0

    for row in iter_jsonl(root / "audit.jsonl"):
        dec = str(row.get("decision") or "unknown").lower()
        out[f"policy_decisions_total_{dec}"] += 1.0

    out["remediation_preview_total"] = float(
        sum(1 for _ in iter_jsonl(root / "remediation_previews.jsonl"))
    )
    out["fleet_endpoints_total"] = float(
        len(
            {
                r.get("endpoint_id")
                for r in iter_jsonl(root / "endpoints.jsonl")
                if r.get("endpoint_id")
            }
        )
    )
    out["audit_replay_success_total"] = float(
        sum(
            1
            for a in iter_jsonl(root / "audit.jsonl")
            if a.get("action") == "replay" and a.get("decision") == "ok"
        )
    )
    if diagnosis_deltas:
        out["diagnosis_duration_seconds"] = round(sum(diagnosis_deltas) / len(diagnosis_deltas), 3)
    return dict(out)


def merge_endpoint_gauges(
    platform_metrics: dict[str, Any], *, data_root: Path | None = None
) -> dict[str, float]:
    """Merge endpoint gauges for toolkit workflows.

    Args:
        platform_metrics: Value supplied by the caller for platform metrics.
        data_root: Value supplied by the caller for data root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    gauges = compute_endpoint_prometheus_gauges(data_root=data_root)
    slo = platform_metrics.get("slo_metrics")
    if isinstance(slo, dict):
        for key in (
            "proxy_drift_incidents_total",
            "remediation_preview_count",
            "blocked_high_risk_action_count",
        ):
            val = slo.get(key)
            if isinstance(val, int | float):
                gauges[key] = float(val)
    return gauges

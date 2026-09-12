"""Compute reliability and SLO metrics from append-only JSONL fixtures."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from platform_core.slo_model import ReliabilityMetrics, SloMetrics
from platform_core.storage import iter_jsonl, platform_data_dir


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    text = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _data_root(data_root: Path | None) -> Path:
    return data_root if data_root is not None else platform_data_dir()


def compute_reliability_metrics(*, data_root: Path | None = None) -> ReliabilityMetrics:
    """Derive portfolio reliability KPIs from local JSONL streams."""
    root = _data_root(data_root)
    signals_path = root / "platform_signals.jsonl"
    browser_ok = 0
    browser_total = 0
    proxy_drift = 0
    false_positive = 0
    fp_denominator = 0
    recover_deltas: list[float] = []
    detect_deltas: list[float] = []
    stickiness_success = 0
    stickiness_total = 0

    for row in iter_jsonl(signals_path):
        kind = str(row.get("kind") or row.get("signal") or "")
        if kind in ("browser_path_ok", "browser_https_ok"):
            browser_ok += 1
            browser_total += 1
        elif kind in ("browser_path_failed", "browser_https_failed"):
            browser_total += 1
        elif kind in ("proxy_registry_change", "proxy_change", "proxy_enable_transition"):
            proxy_drift += 1
        elif kind == "incident_false_positive":
            false_positive += 1
            fp_denominator += 1
        elif kind == "incident_opened":
            fp_denominator += 1
        elif kind == "remediation_stickiness_ok":
            stickiness_success += 1
            stickiness_total += 1
        elif kind == "remediation_stickiness_failed":
            stickiness_total += 1

        detected_at = _parse_iso(row.get("detected_at"))
        occurred_at = _parse_iso(row.get("occurred_at"))
        recovered_at = _parse_iso(row.get("recovered_at"))
        if detected_at and occurred_at:
            detect_deltas.append(max(0.0, (detected_at - occurred_at).total_seconds()))
        if recovered_at and detected_at:
            recover_deltas.append(max(0.0, (recovered_at - detected_at).total_seconds()))

    browser_rate = (browser_ok / browser_total) if browser_total else 0.0
    fp_rate = (false_positive / fp_denominator) if fp_denominator else 0.0
    stickiness = (stickiness_success / stickiness_total) if stickiness_total else 0.0

    return ReliabilityMetrics(
        browser_path_success_rate=round(browser_rate, 4),
        proxy_drift_events_per_day=float(proxy_drift),
        mean_time_to_detect_seconds=(
            round(sum(detect_deltas) / len(detect_deltas), 2) if detect_deltas else None
        ),
        mean_time_to_recover_seconds=(
            round(sum(recover_deltas) / len(recover_deltas), 2) if recover_deltas else None
        ),
        remediation_stickiness_rate=round(stickiness, 4),
        false_positive_rate=round(fp_rate, 4),
    )


def compute_slo_metrics(*, data_root: Path | None = None) -> SloMetrics:
    """Compute SRE-style SLO snapshot from platform JSONL + audit streams."""
    root = _data_root(data_root)
    reliability = compute_reliability_metrics(data_root=root)

    detect_deltas: list[float] = []
    explain_deltas: list[float] = []
    proxy_drift_total = 0
    proof_total = 0
    proof_unavailable = 0
    final_causation = 0

    for row in iter_jsonl(root / "platform_signals.jsonl"):
        kind = str(row.get("kind") or row.get("signal") or "")
        if kind in ("proxy_registry_change", "proxy_change", "proxy_enable_transition"):
            proxy_drift_total += 1
        detected_at = _parse_iso(row.get("detected_at"))
        occurred_at = _parse_iso(row.get("occurred_at"))
        explained_at = _parse_iso(row.get("explained_at"))
        if detected_at and occurred_at:
            detect_deltas.append(max(0.0, (detected_at - occurred_at).total_seconds()))
        if explained_at and detected_at:
            explain_deltas.append(max(0.0, (explained_at - detected_at).total_seconds()))
        elif explained_at and occurred_at:
            explain_deltas.append(max(0.0, (explained_at - occurred_at).total_seconds()))

    for row in iter_jsonl(root / "failure_events.jsonl"):
        if str(row.get("category") or "") in ("proxy_drift", "proxy_change"):
            proxy_drift_total += 1
        proof_total += 1
        ps = str(row.get("proof_status") or row.get("evidence_level") or "")
        if ps in ("unavailable", "observation", "correlation"):
            proof_unavailable += 1
        if ps in ("fixture_proven", "final_causation", "proven") or row.get("final_causation"):
            final_causation += 1

    for row in iter_jsonl(root / "attribution_records.jsonl"):
        proof_total += 1
        level = str(row.get("causation_level") or row.get("proof_level") or "")
        if level in ("FINAL_CAUSATION", "PROVEN_WRITER"):
            final_causation += 1
        elif level in ("UNPROVEN", "CORRELATION_ONLY", ""):
            proof_unavailable += 1

    blocked_high = sum(
        1
        for a in iter_jsonl(root / "audit.jsonl")
        if a.get("decision") == "blocked"
        or str(a.get("action") or "").startswith("remediation_execute")
    )
    preview_count = sum(1 for _ in iter_jsonl(root / "remediation_previews.jsonl"))

    mttd = (
        round(sum(detect_deltas) / len(detect_deltas), 2)
        if detect_deltas
        else reliability.mean_time_to_detect_seconds
    )
    mtexplain = round(sum(explain_deltas) / len(explain_deltas), 2) if explain_deltas else None
    proof_unavail_rate = round(proof_unavailable / proof_total, 4) if proof_total else 0.0
    final_rate = round(final_causation / proof_total, 4) if proof_total else 0.0

    return SloMetrics(
        mean_time_to_detect_seconds=mttd,
        mean_time_to_explain_seconds=mtexplain,
        proxy_drift_incidents_total=proxy_drift_total,
        blocked_high_risk_action_count=blocked_high,
        remediation_preview_count=preview_count,
        proof_unavailable_rate=proof_unavail_rate,
        final_causation_rate=final_rate,
        reliability=reliability,
    )


def reliability_metrics_dict(*, data_root: Path | None = None) -> dict[str, Any]:
    """Provide reliability metrics dict behavior for toolkit workflows.

    Args:
        data_root: Value supplied by the caller for data root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return compute_reliability_metrics(data_root=data_root).model_dump(mode="json")


def slo_metrics_dict(*, data_root: Path | None = None) -> dict[str, Any]:
    """Provide slo metrics dict behavior for toolkit workflows.

    Args:
        data_root: Value supplied by the caller for data root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return compute_slo_metrics(data_root=data_root).model_dump(mode="json")

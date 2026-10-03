"""Prometheus text exposition with labeled counters for the reasoning pipeline."""

from __future__ import annotations

import threading
from typing import Any

_lock = threading.Lock()

# Legacy flat counters (backward compatible)
_flat_counters: dict[str, float] = {
    "platform_http_requests_total": 0.0,
    "platform_correlation_runs_total": 0.0,
    "platform_remediation_preview_total": 0.0,
    "platform_remediation_execute_dry_run_total": 0.0,
    "platform_policy_blocked_total": 0.0,
    "platform_event_ingest_total": 0.0,
    "platform_decision_runs_total": 0.0,
    "platform_policy_allow_total": 0.0,
    "platform_policy_preview_total": 0.0,
}

# Labeled pipeline counters
_labeled_counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}

_PIPELINE_METRICS = (
    "proxy_change_total",
    "hypothesis_generated_total",
    "hypothesis_confirmed_total",
    "policy_allow_total",
    "policy_preview_total",
    "policy_block_total",
    "proof_success_total",
    "proof_failure_total",
)

_METRIC_HELP: dict[str, str] = {
    "proxy_change_total": "Observed proxy drift or registry-change signals (observation tier, not writer proof).",
    "hypothesis_generated_total": "Hypotheses ranked by the correlation engine (ordinal confidence).",
    "hypothesis_confirmed_total": "Hypotheses with CONFIRMED proof status only.",
    "policy_allow_total": "Policy ALLOW outcomes (human-gated; not a safety guarantee).",
    "policy_preview_total": "Policy PREVIEW outcomes (dry-run / preview default).",
    "policy_block_total": "Policy BLOCK outcomes.",
    "proof_success_total": "Proof ladder CONFIRMED results.",
    "proof_failure_total": "Proof REJECTED or INCONCLUSIVE results.",
}


def inc(name: str, amount: float = 1.0) -> None:
    """Inc.

    Args:
        name: The name value supplied by the caller.
        amount: The amount value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    with _lock:
        _flat_counters[name] = _flat_counters.get(name, 0.0) + amount


def inc_labeled(metric: str, labels: dict[str, str], amount: float = 1.0) -> None:
    """Inc labeled.

    Args:
        metric: The metric value supplied by the caller.
        labels: The labels value supplied by the caller.
        amount: The amount value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    ordered = tuple(sorted((str(k), str(v)) for k, v in labels.items()))
    key = (metric, ordered)
    with _lock:
        _labeled_counters[key] = _labeled_counters.get(key, 0.0) + amount


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_prometheus_text(extra_gauges: dict[str, float] | None = None) -> str:
    """Render prometheus text.

    Args:
        extra_gauges: The extra gauges value supplied by the caller.

    Returns:
        The str result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    lines: list[str] = []
    with _lock:
        flat_snapshot = dict(_flat_counters)
        labeled_snapshot = dict(_labeled_counters)

    for key, value in sorted(flat_snapshot.items()):
        metric = key.replace(".", "_")
        help_text = _METRIC_HELP.get(metric, metric.replace("_", " "))
        lines.append(f"# HELP {metric} {help_text}")
        lines.append(f"# TYPE {metric} counter")
        lines.append(f"{metric} {value}")

    if extra_gauges:
        for key, value in sorted(extra_gauges.items()):
            metric = key.replace(".", "_")
            lines.append(f"# HELP {metric} JSONL-derived platform gauge")
            lines.append(f"# TYPE {metric} gauge")
            lines.append(f"{metric} {value}")

    emitted: set[str] = set()
    for metric in _PIPELINE_METRICS:
        if metric not in emitted:
            lines.append(f"# HELP {metric} {_METRIC_HELP.get(metric, metric)}")
            lines.append(f"# TYPE {metric} counter")
            emitted.add(metric)

    for (metric, label_tuple), value in sorted(labeled_snapshot.items()):
        if metric not in _PIPELINE_METRICS:
            continue
        label_str = ",".join(f'{k}="{_escape_label(v)}"' for k, v in label_tuple)
        lines.append(f"{metric}{{{label_str}}} {value}")

    for metric in _PIPELINE_METRICS:
        if not any(k[0] == metric for k in labeled_snapshot):
            lines.append(f"{metric} 0")

    return "\n".join(lines) + "\n"


def gauges_from_platform_metrics(metrics: dict[str, Any]) -> dict[str, float]:
    """Gauges from platform metrics.

    Args:
        metrics: The metrics value supplied by the caller.

    Returns:
        The dict[str, float] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    out: dict[str, float] = {}
    for key in (
        "endpoint_count",
        "open_failure_events",
        "incident_cluster_count",
        "proxy_changes_total",
        "endpoint_heartbeat_total",
        "blocked_action_count",
    ):
        val = metrics.get(key)
        if isinstance(val, (int, float)):
            out[f"platform_{key}"] = float(val)
    rel = metrics.get("reliability_metrics")
    if isinstance(rel, dict):
        for rk, rv in rel.items():
            if isinstance(rv, (int, float)):
                out[f"platform_reliability_{rk}"] = float(rv)
    slo = metrics.get("slo_metrics")
    if isinstance(slo, dict):
        for sk, sv in slo.items():
            if isinstance(sv, (int, float)):
                out[f"platform_slo_{sk}"] = float(sv)
            elif isinstance(sv, dict):
                for nk, nv in sv.items():
                    if isinstance(nv, (int, float)):
                        out[f"platform_slo_{nk}"] = float(nv)
    audit_rows = metrics.get("audit_row_count")
    if isinstance(audit_rows, (int, float)):
        out["platform_audit_volume_total"] = float(audit_rows)
    sre = metrics.get("sre_mttr_metrics")
    if isinstance(sre, dict):
        for key, val in sre.items():
            if isinstance(val, (int, float)):
                out[str(key)] = float(val)
    return out


def reset_metrics_for_tests() -> None:
    """Reset metrics for tests.

    Args:
        None.

    Returns:
        None.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    with _lock:
        _flat_counters.clear()
        _flat_counters.update(
            {
                "platform_http_requests_total": 0.0,
                "platform_correlation_runs_total": 0.0,
                "platform_remediation_preview_total": 0.0,
                "platform_remediation_execute_dry_run_total": 0.0,
                "platform_policy_blocked_total": 0.0,
                "platform_event_ingest_total": 0.0,
                "platform_decision_runs_total": 0.0,
                "platform_policy_allow_total": 0.0,
                "platform_policy_preview_total": 0.0,
            }
        )
        _labeled_counters.clear()

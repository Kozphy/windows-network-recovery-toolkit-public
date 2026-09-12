"""Thread-safe in-memory metrics registry (local / optional; no external services)."""

from __future__ import annotations

import threading
from typing import Literal

MetricKind = Literal["counter", "gauge"]

_lock = threading.Lock()
_counters: dict[str, float] = {}
_gauges: dict[str, float] = {}

# Canonical metric names for enterprise hardening observability.
METRIC_EVIDENCE_COLLECTED = "evidence_events_collected_total"
METRIC_INCIDENTS_CLASSIFIED = "incidents_classified_total"
METRIC_CONTROL_TESTS_EXECUTED = "control_tests_executed_total"
METRIC_POLICY_DECISIONS = "policy_decisions_total"
METRIC_BLOCKED_ACTIONS = "blocked_actions_total"
METRIC_REMEDIATION_PREVIEWS = "remediation_previews_total"
METRIC_AUDIT_APPENDED = "audit_records_appended_total"
METRIC_SPOOL_DEPTH = "spool_queue_depth"
METRIC_AGENT_HEARTBEAT = "agent_heartbeat_total"

_METRIC_HELP: dict[str, str] = {
    METRIC_EVIDENCE_COLLECTED: "Read-only evidence collection cycles (agent and collectors).",
    METRIC_INCIDENTS_CLASSIFIED: "Incidents classified by reliability taxonomy (not malware verdicts).",
    METRIC_CONTROL_TESTS_EXECUTED: "Control tests executed (PASS/FAIL/PARTIAL/NOT_TESTED).",
    METRIC_POLICY_DECISIONS: "Policy engine decisions by outcome label.",
    METRIC_BLOCKED_ACTIONS: "Blocked destructive or policy-denied actions.",
    METRIC_REMEDIATION_PREVIEWS: "Remediation preview generations (dry-run default).",
    METRIC_AUDIT_APPENDED: "Append-only audit/spool JSONL rows written locally.",
    METRIC_SPOOL_DEPTH: "Current agent spool queue depth (line count).",
    METRIC_AGENT_HEARTBEAT: "Read-only agent heartbeat cycles.",
}


def _metric_key(name: str, labels: dict[str, str] | None) -> str:
    if not labels:
        return name
    ordered = ",".join(f'{k}="{_escape_label(v)}"' for k, v in sorted(labels.items()))
    return f"{name}{{{ordered}}}"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def inc_counter(name: str, amount: float = 1.0, *, labels: dict[str, str] | None = None) -> None:
    """Increment a counter metric."""
    key = _metric_key(name, labels)
    with _lock:
        _counters[key] = _counters.get(key, 0.0) + amount


def set_gauge(name: str, value: float, *, labels: dict[str, str] | None = None) -> None:
    """Set a gauge metric."""
    key = _metric_key(name, labels)
    with _lock:
        _gauges[key] = float(value)


def get_counter(name: str, *, labels: dict[str, str] | None = None) -> float:
    """Get counter.

    Args:
        name: name supplied by the caller.
        labels: labels supplied by the caller.

    Returns:
        The computed `float` value.

    Side effects:
        None.
    """
    key = _metric_key(name, labels)
    with _lock:
        return float(_counters.get(key, 0.0))


def get_gauge(name: str, *, labels: dict[str, str] | None = None) -> float:
    """Get gauge.

    Args:
        name: name supplied by the caller.
        labels: labels supplied by the caller.

    Returns:
        The computed `float` value.

    Side effects:
        None.
    """
    key = _metric_key(name, labels)
    with _lock:
        return float(_gauges.get(key, 0.0))


def reset_metrics_for_tests() -> None:
    """Clear all in-memory metrics (test helper)."""
    with _lock:
        _counters.clear()
        _gauges.clear()


def render_prometheus_text() -> str:
    """Render registered counters and gauges in Prometheus text exposition format."""
    lines: list[str] = []
    with _lock:
        counter_snapshot = dict(_counters)
        gauge_snapshot = dict(_gauges)

    emitted_types: set[str] = set()
    for key in sorted(counter_snapshot):
        base = key.split("{", 1)[0]
        if base not in emitted_types:
            lines.append(f"# HELP {base} {_METRIC_HELP.get(base, base)}")
            lines.append(f"# TYPE {base} counter")
            emitted_types.add(base)
        lines.append(f"{key} {counter_snapshot[key]}")

    for key in sorted(gauge_snapshot):
        base = key.split("{", 1)[0]
        if base not in emitted_types:
            lines.append(f"# HELP {base} {_METRIC_HELP.get(base, base)}")
            lines.append(f"# TYPE {base} gauge")
            emitted_types.add(base)
        lines.append(f"{key} {gauge_snapshot[key]}")

    return "\n".join(lines) + ("\n" if lines else "")

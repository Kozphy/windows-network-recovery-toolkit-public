"""In-process Prometheus-style metrics for the technology-risk pipeline.

Module responsibility:
    Thread-safe counters, gauges, and a classification latency histogram summed
    in process memory, rendered as text lines for ``GET /metrics``.

System placement:
    Incremented by evidence/classification/audit/worker paths and classification
    outbox ops (``backend.product_outbox``, ``backend.product_outbox_sweeper``).

Key invariants:
    Metrics are process-local; values reset on API restart. Names listed in
    ``_METRICS`` are documentation of known series; ``inc``/``set_gauge`` also
    accept dynamic names.

Side effects:
    Mutates module-level dicts under a lock.

Limitations:
    Not a multi-instance authoritative store; scrapes reflect one process only.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_counters: dict[str, float] = {}
_histogram_sum: dict[str, float] = {}
_histogram_count: dict[str, float] = {}
_gauges: dict[str, float] = {}

_METRICS = (
    "evidence_events_ingested_total",
    "incidents_classified_total",
    "policy_decisions_total",
    "audit_chain_append_total",
    "audit_chain_verification_failures_total",
    "worker_jobs_total",
    "worker_job_failures_total",
    "domain_events_appended_total",
    "mcp_tool_invocations_total",
    # Classification outbox (product P0 ops) — also emitted dynamically via inc/set_gauge.
    "classification_outbox_pending",
    "classification_outbox_dispatch_attempts_total",
    "classification_outbox_dispatch_success_total",
    "classification_outbox_dispatch_failures_total",
    "classification_outbox_dispatch_skipped_total",
    "classification_outbox_sweep_runs_total",
    "classification_outbox_sweeper_loops_total",
    "classification_outbox_sweeper_errors_total",
)


def inc(name: str, amount: float = 1.0, labels: dict[str, str] | None = None) -> None:
    """Increment a counter (optionally label-encoded into the series key)."""
    key = (
        name
        if not labels
        else f"{name}{{{','.join(f'{k}={v!r}' for k, v in sorted(labels.items()))}}}"
    )
    with _lock:
        _counters[key] = _counters.get(key, 0.0) + amount


def set_gauge(name: str, value: float) -> None:
    """Set a gauge to an absolute value (overwrites prior sample)."""
    with _lock:
        _gauges[name] = value


def inc_classification(classification: str) -> None:
    """Inc classification.

    Args:
        classification: The classification value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    inc("incidents_classified_total", labels={"classification": classification})


def observe_classification_latency(seconds: float) -> None:
    """Observe classification latency.

    Args:
        seconds: The seconds value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    with _lock:
        _histogram_sum["classification_latency_seconds"] = (
            _histogram_sum.get("classification_latency_seconds", 0.0) + seconds
        )
        _histogram_count["classification_latency_seconds"] = (
            _histogram_count.get("classification_latency_seconds", 0.0) + 1.0
        )


def render_trisk_prometheus_lines() -> list[str]:
    """Render trisk prometheus lines.

    Args:
        None.

    Returns:
        The list[str] result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    lines: list[str] = []
    with _lock:
        for k, v in sorted(_counters.items()):
            lines.append(f"{k} {v}")
        for k, v in sorted(_gauges.items()):
            lines.append(f"{k} {v}")
        if _histogram_count.get("classification_latency_seconds"):
            lines.append(
                f"classification_latency_seconds_sum {_histogram_sum.get('classification_latency_seconds', 0.0)}"
            )
            lines.append(
                f"classification_latency_seconds_count {_histogram_count.get('classification_latency_seconds', 0.0)}"
            )
    return lines


def reset_trisk_metrics() -> None:
    """Reset trisk metrics.

    Args:
        None.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    with _lock:
        _counters.clear()
        _gauges.clear()
        _histogram_sum.clear()
        _histogram_count.clear()

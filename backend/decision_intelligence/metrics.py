"""Prometheus metrics for the Decision Intelligence API.

In-process counters/gauges rendered by :func:`render_prometheus_lines` and merged
into the platform ``GET /metrics`` handler.

Thread safety:
    All mutations are guarded by a module lock.

Audit Notes:
    ``decision_failures`` increments on outcome POST where ``success=false``.
    ``decision_accuracy`` is refreshed from outcome-learning replay results.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

_lock = threading.Lock()

_counters: dict[str, float] = {
    "events_total": 0.0,
    "decisions_total": 0.0,
    "decision_failures": 0.0,
}

_gauges: dict[str, float] = {
    "decision_accuracy": 0.0,
    "decision_latency_seconds": 0.0,
}

_latency_sum_seconds: float = 0.0
_latency_count: int = 0

_METRIC_HELP: dict[str, str] = {
    "events_total": "Total decision-intelligence events recorded via API.",
    "decisions_total": "Total decisions recorded via API.",
    "decision_failures": "Outcomes where success=false (ground-truth failure).",
    "decision_accuracy": "Latest batch decision accuracy from outcome learning (0-1).",
    "decision_latency_seconds": "Mean API handler latency for decision-intelligence routes.",
}


def inc_event() -> None:
    """Inc event.

    Args:
        None.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    with _lock:
        _counters["events_total"] += 1.0


def inc_decision() -> None:
    """Inc decision.

    Args:
        None.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    with _lock:
        _counters["decisions_total"] += 1.0


def inc_decision_failure() -> None:
    """Inc decision failure.

    Args:
        None.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    with _lock:
        _counters["decision_failures"] += 1.0


def set_decision_accuracy(value: float) -> None:
    """Set decision accuracy.

    Args:
        value: The value value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    with _lock:
        _gauges["decision_accuracy"] = max(0.0, min(1.0, float(value)))


def record_latency(seconds: float) -> None:
    """Record latency.

    Args:
        seconds: The seconds value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    global _latency_sum_seconds, _latency_count
    with _lock:
        _latency_sum_seconds += max(0.0, seconds)
        _latency_count += 1
        if _latency_count > 0:
            _gauges["decision_latency_seconds"] = _latency_sum_seconds / _latency_count


@contextmanager
def observe_handler_latency() -> Iterator[None]:
    """Observe handler latency.

    Args:
        None.

    Returns:
        The Iterator[None] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    start = time.perf_counter()
    try:
        yield
    finally:
        record_latency(time.perf_counter() - start)


def refresh_accuracy_from_learning(accuracy: float) -> None:
    """Refresh accuracy from learning.

    Args:
        accuracy: The accuracy value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    set_decision_accuracy(accuracy)


def render_prometheus_lines() -> str:
    """Render prometheus lines.

    Args:
        None.

    Returns:
        The str result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    with _lock:
        counters = dict(_counters)
        gauges = dict(_gauges)
    lines: list[str] = []
    for name, value in sorted(counters.items()):
        lines.append(f"# HELP {name} {_METRIC_HELP.get(name, name)}")
        lines.append(f"# TYPE {name} counter")
        lines.append(f"{name} {value}")
    for name, value in sorted(gauges.items()):
        lines.append(f"# HELP {name} {_METRIC_HELP.get(name, name)}")
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {value}")
    return "\n".join(lines) + "\n"


def reset_for_tests() -> None:
    """Reset for tests.

    Args:
        None.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    global _latency_sum_seconds, _latency_count
    with _lock:
        for key in _counters:
            _counters[key] = 0.0
        _gauges["decision_accuracy"] = 0.0
        _gauges["decision_latency_seconds"] = 0.0
        _latency_sum_seconds = 0.0
        _latency_count = 0

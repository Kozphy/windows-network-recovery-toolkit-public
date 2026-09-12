"""Local concurrency benchmark for endpoint analytics — ThreadPoolExecutor only.

Module responsibility:
    Measure the throughput and latency of ``run_endpoint_analytics_pipeline``
    under concurrent load using a ``ThreadPoolExecutor``.  Accepts
    ``inject_failure_every`` for deterministic failure-accounting tests.

System placement:
    Invoked by the ``concurrency-benchmark`` CLI command and benchmark tests.
    Depends only on ``analytics_pipeline.run_endpoint_analytics_pipeline``
    and the standard library.

Key invariants:
    * Only local thread-pool concurrency is measured — no broker, database,
      network, persistence, or multi-host scheduling is involved.
    * Latency percentiles are computed only over completed (non-failed)
      tasks; failures are counted separately.
    * Results are hardware- and runtime-dependent; compare runs with matching
      ``workers`` and ``tasks`` values.

Side effects:
    None beyond in-process thread execution.

Failure modes:
    Raises ``ValueError`` for invalid ``tasks``, ``workers``, or
    ``inject_failure_every`` values.  Pipeline errors inside worker threads
    are caught, counted as failures, and do not abort the benchmark.

Limitations:
    Local ThreadPoolExecutor benchmark only; not a production fleet capacity
    estimate.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from windows_network_toolkit.analytics_pipeline import run_endpoint_analytics_pipeline


def run_concurrency_benchmark(
    *,
    tasks: int = 100,
    workers: int = 4,
    inject_failure_every: int = 0,
) -> dict[str, Any]:
    """Benchmark ``run_endpoint_analytics_pipeline`` under concurrent ThreadPoolExecutor load.

    Submits ``tasks`` analytics pipeline calls to a pool of ``workers`` threads,
    collects per-task latencies, and returns an auditable summary dict.

    Args:
        tasks: Total number of pipeline invocations to run (default 100, ≥ 1).
        workers: Thread pool size (default 4, ≥ 1).
        inject_failure_every: When > 0, every N-th task raises a
            ``RuntimeError`` before the pipeline runs; for failure-accounting
            tests only (default 0 — no injection).

    Returns:
        Dict with keys ``schema_version``, ``tasks``, ``workers``,
        ``completed``, ``failures``, ``failure_ratio``, ``elapsed_ms``,
        ``throughput_tasks_per_s``, ``latency_p50_ms``, ``latency_p95_ms``,
        ``latency_p99_ms``, and ``limitations``.

    Raises:
        ValueError: If ``tasks`` < 1, ``workers`` < 1, or
            ``inject_failure_every`` < 0.
    """
    if tasks < 1:
        raise ValueError("tasks must be >= 1")
    if workers < 1:
        raise ValueError("workers must be >= 1")
    if inject_failure_every < 0:
        raise ValueError("inject_failure_every must be >= 0")

    fixture = {
        "proxy_state": {
            "wininet_proxy_enabled": True,
            "wininet_proxy_server": "127.0.0.1:59081",
            "winhttp_direct_access": True,
            "localhost_port": 59081,
        }
    }

    def one(index: int) -> float:
        """Run one benchmark task and return its elapsed time.

        Args:
            index: Zero-based task index used for deterministic failure injection.

        Returns:
            Elapsed task duration in seconds.

        Raises:
            RuntimeError: When ``inject_failure_every`` selects this task.

        Side effects:
            Executes one in-process endpoint analytics pipeline invocation."""
        started = time.perf_counter()
        if inject_failure_every and (index + 1) % inject_failure_every == 0:
            raise RuntimeError("deterministic injected concurrency failure")
        run_endpoint_analytics_pipeline(fixture=fixture)
        return time.perf_counter() - started

    started = time.perf_counter()
    latencies: list[float] = []
    failures = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(one, i) for i in range(tasks)]
        for future in as_completed(futures):
            try:
                latencies.append(future.result())
            except Exception:
                failures += 1
    elapsed = time.perf_counter() - started

    ordered = sorted(latencies)

    def percentile(pct: float) -> float:
        """Return a percentile value from completed task latencies.

        Args:
            pct: Percentile number, such as ``50``, ``95``, or ``99``.

        Returns:
            Latency in seconds from the ordered sample, or ``0.0`` when no tasks completed.

        Side effects:
            None."""
        if not ordered:
            return 0.0
        idx = min(int(len(ordered) * pct / 100), len(ordered) - 1)
        return ordered[idx]

    completed = len(latencies)
    return {
        "schema_version": "concurrency-benchmark.v1",
        "tasks": tasks,
        "workers": workers,
        "completed": completed,
        "failures": failures,
        "failure_ratio": round(failures / tasks, 4),
        "elapsed_ms": round(elapsed * 1000, 2),
        "throughput_tasks_per_s": round(completed / elapsed, 2) if elapsed else 0.0,
        "latency_p50_ms": round(percentile(50) * 1000, 2),
        "latency_p95_ms": round(percentile(95) * 1000, 2),
        "latency_p99_ms": round(percentile(99) * 1000, 2),
        "limitations": [
            "Local ThreadPoolExecutor benchmark only; not production fleet capacity.",
            "No broker, network, database, persistence, or multi-host scheduling is measured.",
            "Python runtime and host hardware materially affect results.",
        ],
    }

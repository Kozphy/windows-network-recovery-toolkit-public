"""Benchmark reproducibility and regression-quality helpers.

Module responsibility:
    Provide two capabilities that keep portfolio benchmarks honest:
    (1) ``capture_environment_manifest`` — snapshot privacy-safe host and
    runtime metadata so benchmark results can be interpreted and compared;
    (2) ``evaluate_benchmark_regression`` — compare a benchmark summary dict
    against opt-in ``BenchmarkThresholds`` and produce an auditable PASS/FAIL
    artifact.

System placement:
    Used by ``fleet_benchmark.run_fleet_benchmark`` (environment manifest)
    and by CI regression checks (threshold evaluation).  No OS writes,
    network calls, or process spawning.

Key invariants:
    * ``capture_environment_manifest`` deliberately excludes hostnames,
      usernames, and network identifiers so the output can be committed to
      version control without leaking workstation identity.
    * ``BenchmarkThresholds`` fields are all ``None`` by default — thresholds
      are opt-in; an unconfigured check reports ``NOT_CONFIGURED`` rather than
      PASS or FAIL.
    * ``evaluate_benchmark_regression`` returns ``NOT_CONFIGURED`` overall
      when no thresholds are set, and ``PASS`` only when at least one
      configured check passes and none fail.

Side effects:
    ``capture_environment_manifest`` reads environment variables
    (``GITHUB_SHA``, ``GIT_COMMIT``, ``CI``) and ``os.cpu_count()``.
    All other functions are pure.

Failure modes:
    No exceptions are raised by these helpers under normal conditions.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class BenchmarkThresholds:
    """Portable guardrails for comparing like-for-like benchmark runs.

    All fields are ``None`` by default; set only the thresholds that make
    sense for the current execution environment and fixture set.

    Attributes:
        max_p95_ms: Maximum acceptable p95 per-endpoint latency in
            milliseconds, or ``None`` to skip this check.
        max_p99_ms: Maximum acceptable p99 per-endpoint latency in
            milliseconds, or ``None`` to skip.
        min_throughput_eps: Minimum acceptable analytics throughput in
            endpoint executions per second, or ``None`` to skip.
        max_unknown_ratio: Maximum acceptable ratio of unknown / insufficient-
            data classifications (0.0–1.0), or ``None`` to skip.
        max_execution_failure_ratio: Maximum acceptable execution failure
            ratio (default 0.0 — any failure fails the check).
    """

    max_p95_ms: float | None = None
    max_p99_ms: float | None = None
    min_throughput_eps: float | None = None
    max_unknown_ratio: float | None = None
    max_execution_failure_ratio: float | None = 0.0


def capture_environment_manifest() -> dict[str, Any]:
    """Return low-risk metadata needed to interpret a local benchmark run.

    Host names, usernames, environment variables, and network identifiers are
    intentionally excluded so reports can be committed without leaking workstation
    identity. Commit SHA may be supplied by CI through ``GITHUB_SHA``.
    """

    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform_system": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
        "executable_bits": 64 if sys.maxsize > 2**32 else 32,
        "git_commit": os.getenv("GITHUB_SHA") or os.getenv("GIT_COMMIT") or "unknown",
        "ci": bool(os.getenv("CI")),
    }


def evaluate_benchmark_regression(
    summary: dict[str, Any],
    thresholds: BenchmarkThresholds,
) -> dict[str, Any]:
    """Evaluate explicit thresholds and return an auditable PASS/FAIL artifact.

    Thresholds are intentionally opt-in for latency and throughput because local
    hardware varies. CI can pin thresholds once runners and fixtures are stable.
    """

    checks: list[dict[str, Any]] = []

    def add_check(name: str, observed: float, operator: str, limit: float | None) -> None:
        """Record one threshold comparison in the benchmark check list.

        Args:
            name: Stable check identifier.
            observed: Observed metric value from the benchmark summary.
            operator: Comparison operator, either ``"<="`` or ``">="``.
            limit: Configured threshold value, or ``None`` when the check is disabled.

        Returns:
            None.

        Side effects:
            Appends a check dict to the enclosing ``checks`` list."""
        if limit is None:
            checks.append(
                {
                    "name": name,
                    "status": "NOT_CONFIGURED",
                    "observed": observed,
                    "operator": operator,
                    "threshold": None,
                }
            )
            return
        passed = observed <= limit if operator == "<=" else observed >= limit
        checks.append(
            {
                "name": name,
                "status": "PASS" if passed else "FAIL",
                "observed": observed,
                "operator": operator,
                "threshold": limit,
            }
        )

    attempted = int(summary.get("measured_endpoints", 0) or 0)
    failures = int(summary.get("execution_failures", 0) or 0)
    failure_ratio = failures / attempted if attempted else 0.0

    add_check(
        "latency_p95_ms",
        float(summary.get("latency_p95_ms", 0.0) or 0.0),
        "<=",
        thresholds.max_p95_ms,
    )
    add_check(
        "latency_p99_ms",
        float(summary.get("latency_p99_ms", 0.0) or 0.0),
        "<=",
        thresholds.max_p99_ms,
    )
    add_check(
        "analytics_throughput_eps",
        float(summary.get("analytics_throughput_eps", 0.0) or 0.0),
        ">=",
        thresholds.min_throughput_eps,
    )
    add_check(
        "unknown_classification_ratio",
        float(summary.get("unknown_classification_ratio", 0.0) or 0.0),
        "<=",
        thresholds.max_unknown_ratio,
    )
    add_check(
        "execution_failure_ratio", failure_ratio, "<=", thresholds.max_execution_failure_ratio
    )

    configured = [check for check in checks if check["status"] != "NOT_CONFIGURED"]
    failures_found = [check for check in configured if check["status"] == "FAIL"]
    status = "FAIL" if failures_found else ("PASS" if configured else "NOT_CONFIGURED")

    return {
        "status": status,
        "thresholds": asdict(thresholds),
        "checks": checks,
        "configured_checks": len(configured),
        "failed_checks": len(failures_found),
        "limitations": [
            "Regression thresholds are meaningful only for comparable fixtures and execution environments.",
            "Local synthetic benchmark thresholds are engineering guardrails, not production SLOs or SLAs.",
        ],
    }

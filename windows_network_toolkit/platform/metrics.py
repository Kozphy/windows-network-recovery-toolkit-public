"""Platform metrics facade for the Endpoint Reliability Decision Platform.

Module responsibility:
    Expose a single ``compute_erp_metrics()`` function that merges ERP-level
    metadata with metrics delegated to ``platform_core.metrics``.  Provides a
    stable interface for the operator CLI and API metrics endpoints.

System placement:
    Called by CLI commands and API endpoints that expose platform health or
    observability data.  Depends optionally on ``platform_core.metrics``; if
    that import fails (e.g. in a stripped installation) the function
    degrades gracefully to an empty ``platform_metrics`` dict.

Key invariants:
    * ``dry_run_default=True`` is always present in the returned dict,
      reflecting the platform's default safe-mode posture.
    * Failures in ``platform_core.metrics`` are silently swallowed (bare
      ``except Exception``) so that a metrics endpoint failure never
      cascades into a service health failure.

Side effects:
    None — read-only aggregation.

Failure modes:
    ``platform_core.metrics`` import or invocation errors are caught and
    produce an empty ``{}`` for ``platform_metrics``.
"""

from __future__ import annotations

from typing import Any


def compute_erp_metrics() -> dict[str, Any]:
    """Compute aggregated ERP platform metrics.

    Attempts to delegate to ``platform_core.metrics.compute_platform_metrics``
    for base metrics; silently falls back to ``{}`` on any import or runtime
    error.

    Returns:
        Dict with keys:

        * ``"service"`` — fixed string ``"endpoint-reliability-decision-platform"``.
        * ``"platform_metrics"`` — delegated metrics dict (empty on failure).
        * ``"dry_run_default"`` — always ``True``.
    """
    try:
        from platform_core.metrics import compute_platform_metrics

        base = compute_platform_metrics()
    except Exception:  # noqa: BLE001
        base = {}
    return {
        "service": "endpoint-reliability-decision-platform",
        "platform_metrics": base,
        "dry_run_default": True,
    }

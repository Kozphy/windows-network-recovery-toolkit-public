"""SLO evaluation helpers built on reliability metrics."""

from __future__ import annotations

from typing import Any

from platform_core.reliability_metrics import compute_reliability_metrics


def evaluate_slos(*, data_root=None) -> dict[str, Any]:
    """Evaluate slos for toolkit workflows.

    Args:
        data_root: Value supplied by the caller for data root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    metrics = compute_reliability_metrics(data_root=data_root)
    targets = {
        "browser_path_success_rate_min": 0.95,
        "false_positive_rate_max": 0.10,
        "remediation_stickiness_rate_min": 0.80,
    }
    status = {
        "browser_path_success_rate": metrics.browser_path_success_rate
        >= targets["browser_path_success_rate_min"],
        "false_positive_rate": metrics.false_positive_rate <= targets["false_positive_rate_max"],
        "remediation_stickiness_rate": metrics.remediation_stickiness_rate
        >= targets["remediation_stickiness_rate_min"],
    }
    return {
        "metrics": metrics.model_dump(mode="json"),
        "targets": targets,
        "slo_met": all(status.values()),
        "checks": status,
    }

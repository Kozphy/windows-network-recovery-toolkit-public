"""Generate JSON and Markdown learning reports."""

from __future__ import annotations

import json
from typing import Any

from .learning import compute_learning_metrics
from .models import LearningMetrics, LearningReport, OutcomeEvaluation


def _summary_text(metrics: LearningMetrics) -> str:
    return (
        f"Evaluated {metrics.sample_count} decision outcomes — "
        f"accuracy={metrics.decision_accuracy:.2%}, "
        f"precision={metrics.decision_precision:.2%}, "
        f"recall={metrics.decision_recall:.2%}, "
        f"average_cost={metrics.average_cost:.2f}."
    )


def build_learning_report(
    evaluations: list[OutcomeEvaluation],
    *,
    content_digest: str = "",
) -> LearningReport:
    """Assemble a full learning report with metrics and evaluations."""
    metrics = compute_learning_metrics(evaluations)
    return LearningReport(
        metrics=metrics,
        evaluations=evaluations,
        content_digest=content_digest,
        summary=_summary_text(metrics),
    )


def report_to_json(report: LearningReport, *, indent: int = 2) -> str:
    """Provide report to json behavior for toolkit workflows.

    Args:
        report: Value supplied by the caller for report.
        indent: Value supplied by the caller for indent.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    payload = report.model_dump(mode="json")
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def report_to_markdown(report: LearningReport) -> str:
    """Provide report to markdown behavior for toolkit workflows.

    Args:
        report: Value supplied by the caller for report.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    m = report.metrics
    lines = [
        "# Outcome Learning Report",
        "",
        report.summary,
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| decision_accuracy | {m.decision_accuracy:.4f} |",
        f"| decision_precision | {m.decision_precision:.4f} |",
        f"| decision_recall | {m.decision_recall:.4f} |",
        f"| average_cost | {m.average_cost:.4f} |",
        f"| average_time_to_resolution | {m.average_time_to_resolution:.4f} |",
        f"| sample_count | {m.sample_count} |",
        "",
        "## Confusion summary",
        "",
        f"- true_positives: {m.true_positives}",
        f"- true_negatives: {m.true_negatives}",
        f"- false_positives: {m.false_positives}",
        f"- false_negatives: {m.false_negatives}",
        "",
    ]
    if report.content_digest:
        lines.extend(["## Replay", "", f"`content_digest`: `{report.content_digest}`", ""])

    if report.evaluations:
        lines.extend(["## Evaluations", ""])
        for row in report.evaluations:
            status = "correct" if row.correct else "incorrect"
            lines.append(
                f"- **{row.decision_id}** ({row.classification}, {status}) — "
                f"cost={row.cost:.2f}, ttr={row.time_to_resolution:.2f}s"
            )
            if row.notes:
                lines.append(f"  - {row.notes}")
        lines.append("")

    return "\n".join(lines)


def metrics_payload(metrics: LearningMetrics) -> dict[str, Any]:
    """Provide metrics payload behavior for toolkit workflows.

    Args:
        metrics: Value supplied by the caller for metrics.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    return {
        "decision_accuracy": metrics.decision_accuracy,
        "decision_precision": metrics.decision_precision,
        "decision_recall": metrics.decision_recall,
        "average_cost": metrics.average_cost,
        "average_time_to_resolution": metrics.average_time_to_resolution,
        "sample_count": metrics.sample_count,
    }

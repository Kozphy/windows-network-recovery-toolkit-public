"""Markdown and JSON report rendering for AI eval suite results.

Transforms an ``EvalReport`` aggregate into human-readable markdown or JSON-serializable
dicts for CLI and CI consumption. Reports include taxonomy distribution, policy gates,
and high-risk case lists.

Note:
    Rendered reports echo baseline limitations — they are not deployment authorization.
"""

from __future__ import annotations

from typing import Any

from .failure_taxonomy import FAILURE_DESCRIPTIONS, FailureLabel
from .schemas import EvalReport


def render_eval_json(report: EvalReport) -> dict[str, Any]:
    """Render eval json.

    Args:
        report: report supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.
    """
    return report.model_dump(mode="json")


def render_eval_markdown(report: EvalReport) -> str:
    """Render eval markdown.

    Args:
        report: report supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.
    """
    lines: list[str] = [
        "# AI Evals Feedback Loop Report",
        "",
        "## Executive summary",
        "",
        f"- Total cases: **{report.total_cases}**",
        f"- Pass: **{report.pass_count}** | Fail: **{report.fail_count}** | Partial: **{report.partial_count}**",
        f"- High-risk cases (human review): **{len(report.high_risk_cases)}**",
        "",
        "## Eval dataset overview",
        "",
        f"Schema: `{report.schema_version}`",
        f"Generated: {report.created_at}",
        "",
        report.positioning,
        "",
        "## Metrics summary",
        "",
        "| Case ID | Status | Confidence | Policy | Failure labels |",
        "|---------|--------|------------|--------|----------------|",
    ]

    for result in report.results:
        labels = ", ".join(label.value for label in result.failure_labels) or "—"
        lines.append(
            f"| {result.case_id} | {result.status} | {result.confidence_level} | "
            f"{result.policy_decision.gate.value} | {labels} |"
        )

    lines.extend(
        [
            "",
            "## Failure taxonomy distribution",
            "",
            "| Label | Count | Description |",
            "|-------|-------|-------------|",
        ]
    )

    all_labels = sorted(report.taxonomy_distribution.keys())
    if not all_labels:
        all_labels = [FailureLabel.CORRECT.value]
    for label_key in all_labels:
        count = report.taxonomy_distribution.get(label_key, 0)
        try:
            desc = FAILURE_DESCRIPTIONS[FailureLabel(label_key)]
        except ValueError:
            desc = "—"
        lines.append(f"| {label_key} | {count} | {desc} |")

    lines.extend(["", "## Policy decisions", "", "| Gate | Count |", "|------|-------|"])
    for gate, count in sorted(report.policy_distribution.items()):
        lines.append(f"| {gate} | {count} |")

    lines.extend(["", "## High-risk cases requiring human review", ""])
    if report.high_risk_cases:
        for case_id in report.high_risk_cases:
            match = next((r for r in report.results if r.case_id == case_id), None)
            if match:
                lines.append(
                    f"- **{case_id}**: {match.policy_decision.gate.value} — "
                    f"{match.policy_decision.rationale}"
                )
    else:
        lines.append("- None in this run.")

    lines.extend(["", "## Per-case detail", ""])
    for result in report.results:
        lines.append(f"### {result.case_id}")
        lines.append(f"- Status: `{result.status}`")
        lines.append(f"- Checks: {', '.join(result.checks_run)}")
        lines.append(f"- Recommendation: {result.recommendation}")
        if result.limitations:
            lines.append("- Limitations:")
            for lim in result.limitations:
                lines.append(f"  - {lim}")
        lines.append("")

    lines.extend(["", "## Limitations", ""])
    for lim in report.limitations:
        lines.append(f"- {lim}")
    lines.extend(
        [
            "",
            "## Recommended next actions",
            "",
            "- Re-run eval suite after prompt or retrieval changes.",
            "- Route `REQUIRE_HUMAN_REVIEW` and `BLOCK` cases to reviewer queue before partner release.",
            "- Treat `ALLOW` as structured signal only — not deployment authorization.",
            "",
            "---",
            "",
            "*This report is not a formal model safety certification.*",
        ]
    )
    return "\n".join(lines)

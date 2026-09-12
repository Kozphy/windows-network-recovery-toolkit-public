"""Executive evidence report — portfolio-grade leadership summary."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core.cloud_governance import summarize_cloud_recommendations
from src.platform_core.finops import build_finops_export
from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from src.platform_core.risk.risk_matrix import build_risk_matrix

SCHEMA_VERSION = "executive_evidence_report.v1"


def build_executive_evidence_report(
    *,
    risk_register_path: Path | str | None = None,
    cloud_fixture_path: Path | str | None = None,
    finops_fixture_path: Path | str | None = None,
    audit_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Combine risk matrix, cloud governance, and FinOps into one executive payload."""
    risk_matrix = build_risk_matrix(register_path=risk_register_path)
    cloud = summarize_cloud_recommendations(fixture_path=cloud_fixture_path)
    finops = build_finops_export(fixture_path=finops_fixture_path)

    rows = risk_matrix.get("matrix_rows") or []
    top_risks = sorted(rows, key=lambda r: r.get("severity_score", 0), reverse=True)[:5]
    control_gaps = [
        r for r in rows if r.get("confidence", 0) < 0.6 or r.get("severity_score", 0) >= 12
    ]

    audit_summary: dict[str, Any] = {}
    if audit_dir is not None:
        from src.platform_core.analytics.risk_kpi import build_risk_kpi_summary

        audit_summary = build_risk_kpi_summary(Path(audit_dir))

    limitations = list(risk_matrix.get("limitations") or [])
    limitations.extend(cloud.get("limitations") or [])
    limitations.extend(finops.get("limitations") or [])
    limitations.append("Executive report aggregates evidence — not audit opinion or attestation.")

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "executive_summary": {
            "total_risks": risk_matrix.get("summary", {}).get("total_risks", 0),
            "high_severity_risks": risk_matrix.get("summary", {}).get("high_severity_count", 0),
            "cloud_recommendations": cloud.get("total_recommendations", 0),
            "estimated_monthly_savings_usd": cloud.get("estimated_monthly_savings_usd", 0.0),
            "total_monthly_cost_usd": finops.get("summary", {}).get("total_monthly_cost_usd", 0.0),
            "audit_incidents": audit_summary.get("kpis", {}).get("total_incidents"),
        },
        "top_risks": top_risks,
        "top_cost_saving_opportunities": cloud.get("top_savings_opportunities") or [],
        "control_gaps": control_gaps,
        "risk_matrix_summary": risk_matrix.get("summary"),
        "cloud_governance_summary": {
            "by_pillar": cloud.get("by_pillar"),
            "by_provider": cloud.get("by_provider"),
        },
        "finops_summary": finops.get("summary"),
        "audit_kpi_summary": audit_summary.get("kpis") if audit_summary else None,
        "recommended_next_actions": [
            "Review top severity risks with evidence tier and limitations attached.",
            "Prioritize cost recommendations with highest illustrative savings — validate in billing.",
            "Close control gaps where confidence is below governance threshold.",
            "Run powerbi-export for committee dashboards; keep JSONL as source of truth.",
            "Remediation remains preview-only unless human-confirmed with audit evidence.",
        ],
        "limitations": list(dict.fromkeys(limitations)),
    }
    return attach_governance_envelope(payload, limitations=payload["limitations"])


def format_executive_evidence_markdown(report: dict[str, Any]) -> str:
    """Render executive evidence report as Markdown."""
    summary = report.get("executive_summary") or {}
    lines = [
        "# Executive Evidence Report",
        "",
        "## Executive summary",
        "",
        f"- **Total risks:** {summary.get('total_risks', 0)}",
        f"- **High severity risks:** {summary.get('high_severity_risks', 0)}",
        f"- **Cloud recommendations:** {summary.get('cloud_recommendations', 0)}",
        f"- **Illustrative monthly savings:** ${float(summary.get('estimated_monthly_savings_usd') or 0):.2f}",
        f"- **Illustrative monthly cloud spend:** ${float(summary.get('total_monthly_cost_usd') or 0):.2f}",
        "",
        "## Top risks",
        "",
    ]
    for row in report.get("top_risks") or []:
        lines.append(
            f"- **{row.get('risk_id')}** (severity {row.get('severity_score')}): "
            f"{row.get('risk_description')} — control {row.get('recommended_control')}"
        )

    lines.extend(["", "## Top cost-saving opportunities", ""])
    for row in report.get("top_cost_saving_opportunities") or []:
        lines.append(
            f"- **{row.get('recommendation_id')}**: {row.get('title')} — "
            f"${float(row.get('estimated_monthly_savings_usd') or 0):.2f}/mo"
        )

    lines.extend(["", "## Control gaps", ""])
    gaps = report.get("control_gaps") or []
    if not gaps:
        lines.append("- No material control gaps identified in mock register.")
    else:
        for row in gaps:
            lines.append(
                f"- **{row.get('risk_id')}**: confidence {row.get('confidence')} — "
                f"{row.get('recommended_action')}"
            )

    lines.extend(["", "## Evidence limitations", ""])
    for lim in report.get("limitations") or []:
        lines.append(f"- {lim}")

    lines.extend(["", "## Recommended next actions", ""])
    for action in report.get("recommended_next_actions") or []:
        lines.append(f"- {action}")

    return "\n".join(lines) + "\n"


def export_executive_evidence_report(
    *,
    risk_register_path: Path | str | None = None,
    cloud_fixture_path: Path | str | None = None,
    finops_fixture_path: Path | str | None = None,
    audit_dir: Path | str | None = None,
    out_path: Path | None = None,
    fmt: str = "markdown",
) -> dict[str, Any]:
    """Build and optionally write executive evidence report."""
    report = build_executive_evidence_report(
        risk_register_path=risk_register_path,
        cloud_fixture_path=cloud_fixture_path,
        finops_fixture_path=finops_fixture_path,
        audit_dir=audit_dir,
    )
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            out_path.write_text(format_executive_evidence_markdown(report), encoding="utf-8")
        report["export_path"] = str(out_path.resolve())
    report["export_format"] = fmt
    return report

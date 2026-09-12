"""Governance report built from audit directories."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.platform_core.analytics.risk_kpi import build_risk_kpi_summary, format_risk_kpi_markdown
from src.platform_core.analytics.summary import (
    _classification_of,
    _load_audit_records,
    build_analytics_summary,
)
from src.platform_core.controls.control_test import run_control_test_suite
from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from src.platform_core.governance.report_sections import (
    AI_TRANSPARENCY_SECTION,
    GOVERNANCE_PRINCIPLES,
    NON_CLAIMS,
)
from src.platform_core.risk.business_impact import estimate_business_impact
from src.platform_core.risk.business_impact_mapping import map_business_impact

SCHEMA_VERSION = "audit_governance_report.v2"


def _load_risk_register(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.is_file():
        default = (
            Path(__file__).resolve().parents[3]
            / "tests"
            / "fixtures"
            / "risk_register"
            / "sample_risk_register.json"
        )
        if default.is_file():
            path = default
        else:
            return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    return list(data.get("risks") or [])


def _dominant_classification(records: list[dict[str, Any]]) -> str | None:
    for row in records:
        cls = _classification_of(row)
        if cls:
            return cls
    return None


def _evidence_timeline(records: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    timeline = []
    for row in sorted(records, key=lambda r: str(r.get("timestamp") or ""))[:limit]:
        timeline.append(
            {
                "timestamp": row.get("timestamp"),
                "incident_id": row.get("incident_id") or row.get("case_id"),
                "event": row.get("action") or row.get("command") or "observation",
                "classification": _classification_of(row),
            }
        )
    return timeline


def _human_review_queue(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from src.platform_core.governance.human_review import items_needing_review

    return items_needing_review(records)


def _top_risk_themes(kpis: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    by_cls = kpis.get("incidents_by_classification") or {}
    themes = []
    for cls, count in sorted(by_cls.items(), key=lambda x: -x[1])[:limit]:
        mapping = map_business_impact(cls)
        themes.append(
            {
                "classification": cls,
                "incident_count": count,
                "operational_risk": mapping.operational_risk,
                "suggested_forum": mapping.suggested_forum,
            }
        )
    return themes


def _high_risk_unresolved(kpis: dict[str, Any], records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    high_count = int(kpis.get("high_residual_risk_count") or 0)
    unresolved = int(kpis.get("unresolved_incident_count") or 0)
    items: list[dict[str, Any]] = []
    if high_count:
        items.append(
            {
                "category": "high_residual_risk",
                "count": high_count,
                "summary": "Incidents with high-residual classifications remain open for governance review.",
            }
        )
    if unresolved:
        items.append(
            {
                "category": "unresolved_incidents",
                "count": unresolved,
                "summary": "Unresolved incidents lack closed/resolved status in audit trail.",
            }
        )
    for row in records:
        cls = _classification_of(row) or ""
        if cls in ("POSSIBLE_MITM_RISK", "REVERTER_SUSPECTED") and str(row.get("status", "")).lower() not in (
            "resolved",
            "closed",
        ):
            items.append(
                {
                    "incident_id": row.get("incident_id") or row.get("case_id"),
                    "classification": cls,
                    "summary": f"Open {cls} incident requires proof-tier context before escalation.",
                }
            )
    return items[:15]


def _control_test_summary(control_tests: list[Any]) -> dict[str, Any]:
    counts: dict[str, int] = {"PASS": 0, "FAIL": 0, "PARTIAL": 0, "NOT_TESTED": 0, "EXCEPTION": 0, "INSUFFICIENT_EVIDENCE": 0}
    for test in control_tests:
        raw = test.result if hasattr(test, "result") else test.get("result")
        key = str(raw)
        if key == "INSUFFICIENT_EVIDENCE":
            counts["NOT_TESTED"] += 1
        elif key == "EXCEPTION":
            counts["PARTIAL"] += 1
        elif key in counts:
            counts[key] += 1
        else:
            counts["NOT_TESTED"] += 1
    return {
        "total_tests": len(control_tests),
        "by_result": counts,
        "design_effectiveness_note": "Control tests evaluate design for audit-backed scope — not SOX attestation.",
    }


def build_audit_governance_report(
    audit_dir: Path,
    *,
    risk_register_path: Path | None = None,
    format: str = "json",
) -> str | dict[str, Any]:
    """Build audit governance report.

    Args:
        audit_dir: audit dir supplied by the caller.
        risk_register_path: risk register path supplied by the caller.
        format: format supplied by the caller.

    Returns:
        The computed `str | dict[str, Any]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    records, files, _ = _load_audit_records(audit_dir)
    kpi_payload = build_risk_kpi_summary(audit_dir)
    analytics = build_analytics_summary(audit_dir)
    control_tests = run_control_test_suite(audit_records=records)
    risk_register = _load_risk_register(risk_register_path)
    dominant_cls = _dominant_classification(records)
    business_impact = estimate_business_impact(classification=dominant_cls)

    integrity = kpi_payload.get("audit_integrity") or {}
    chain_ok = integrity.get("hash_chain_invalid_count", 0) == 0
    kpis = kpi_payload.get("kpis") or {}
    human_queue = _human_review_queue(records)
    themes = _top_risk_themes(kpis)
    high_risk = _high_risk_unresolved(kpis, records)
    ctrl_summary = _control_test_summary(control_tests)

    executive_narrative = (
        "This report summarizes endpoint reliability incidents for a technology risk committee. "
        f"During the review period, {kpis.get('total_incidents', 0)} incident(s) were recorded with "
        f"{kpis.get('unresolved_incident_count', 0)} unresolved and "
        f"{kpis.get('high_residual_risk_count', 0)} high-residual item(s). "
        "All classifications are evidence-backed triage labels — not malware or compromise verdicts. "
        "Remediation remains preview-only unless typed confirmation and audit logging are satisfied."
    )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "command": "governance-report",
        "executive_summary": executive_narrative,
        "governance_principles": GOVERNANCE_PRINCIPLES,
        "incident_volume_by_classification": dict(kpis.get("incidents_by_classification") or {}),
        "top_recurring_risk_themes": themes,
        "incident_overview": {
            "total_incidents": kpis.get("total_incidents", 0),
            "unresolved": kpis.get("unresolved_incident_count", 0),
            "high_residual_risk": kpis.get("high_residual_risk_count", 0),
        },
        "high_risk_unresolved_items": high_risk,
        "human_review_queue": human_queue,
        "evidence_timeline": _evidence_timeline(records),
        "evidence_tier_explanation": {
            "T0_OBSERVATION_ONLY": "Snapshot or symptom — not proof.",
            "T1_LOCAL_CONFIG_EVIDENCE": "Registry/proxy configuration — not causation.",
            "T2_RUNTIME_CORROBORATION": "Listener/path contrast — not malware verdict.",
            "T3_BEHAVIORAL_REPRODUCTION": "Structured proof checks — still not compromise confirmation.",
            "T4_OPERATOR_CONFIRMED": "Human-confirmed action — does not prove absence of threat.",
        },
        "risk_register_summary": risk_register,
        "control_test_results": [t.model_dump() for t in control_tests],
        "control_test_summary": ctrl_summary,
        "policy_decisions": kpis.get("policy_decisions_by_type", {}),
        "remediation_previews": {
            "count": kpis.get("remediation_previews_count", 0),
            "confirmed_executions": kpis.get("confirmed_remediations_count", 0),
        },
        "business_impact_estimate": business_impact.model_dump(),
        "business_impact_forum_mapping": (
            map_business_impact(dominant_cls).model_dump() if dominant_cls else {}
        ),
        "analytics_summary": analytics.get("counts"),
        "risk_kpis": kpis,
        "audit_chain_verification": {
            "verified": chain_ok,
            "details": integrity,
        },
        "ai_usage_transparency": AI_TRANSPARENCY_SECTION,
        "limitations_and_non_claims": NON_CLAIMS
        + list(kpi_payload.get("limitations") or [])
        + business_impact.limitations
        + [
            "Governance report aggregates audit JSONL — does not replace formal audit opinion.",
            "MITRE ATT&CK references are triage context only, not attribution.",
        ],
        "recommended_next_actions": [
            "Review human-review queue items with proof-tier and business-impact mapping.",
            "Address high-residual unresolved incidents before attesting control effectiveness.",
            "Run mature control tests on representative case fixtures quarterly.",
            "Verify audit hash chain integrity before exporting to risk warehouse.",
            "Keep remediation preview-only until typed confirmation and rollback plan.",
        ],
        "unsafe_inferences_blocked": [
            "Malware or compromise verdict blocked without registry writer proof tier.",
            "MITM accusation blocked without path proof contrast and limitations.",
            "Process listener correlation blocked from registry writer attribution.",
            "Remote proxy configured inference blocked when after_proxy_server is empty.",
            "AI output does not authorize execution — policy gate and human review required.",
        ],
        "appendix": {
            "audit_integrity_verification": {
                "verified": chain_ok,
                "procedure": "Replay audit JSONL through hash-chain verifier; compare genesis-linked hashes.",
                "details": integrity,
            },
        },
        "source": {
            "audit_dir": str(audit_dir.resolve()),
            "files": [p.name for p in files],
        },
        "limitations": [],  # populated below for backward compatibility
    }
    payload["limitations"] = list(payload["limitations_and_non_claims"])
    payload = attach_governance_envelope(payload, dry_run=True, requires_confirmation=True)

    if format == "json":
        return payload

    md = _format_markdown(payload, kpi_payload)
    if format == "html":
        return _markdown_to_html(md)
    return md


def _format_markdown(payload: dict[str, Any], kpi_payload: dict[str, Any]) -> str:
    kpi_md = format_risk_kpi_markdown(kpi_payload)
    lines = [
        "# Technology Risk Governance Report (Audit-Backed)",
        "",
        "## Executive Summary",
        "",
        payload["executive_summary"],
        "",
        "### Incident volume by classification",
        "",
    ]
    for cls, count in (payload.get("incident_volume_by_classification") or {}).items():
        lines.append(f"- **{cls}**: {count}")
    lines.extend(["", "### Top recurring risk themes", ""])
    for theme in payload.get("top_recurring_risk_themes") or []:
        lines.append(
            f"- **{theme['classification']}** ({theme['incident_count']}): {theme['operational_risk']}"
        )
    lines.extend(["", "### Control test summary", ""])
    summary = payload.get("control_test_summary") or {}
    for result, count in (summary.get("by_result") or {}).items():
        if count:
            lines.append(f"- {result}: {count}")
    lines.extend(["", "### High-risk unresolved items", ""])
    for item in payload.get("high_risk_unresolved_items") or []:
        lines.append(f"- {item.get('summary') or item}")
    lines.extend(["", "### Human-review queue", ""])
    queue = payload.get("human_review_queue") or []
    if queue:
        for item in queue:
            lines.append(f"- **{item.get('classification')}** — {item.get('reason')}")
    else:
        lines.append("- No accusatory-adjacent classifications in current audit scope.")
    lines.extend(["", "## Risk KPIs", "", kpi_md, "", "## Control Test Results", ""])
    for test in payload.get("control_test_results") or []:
        lines.append(f"- **{test['control_id']}** ({test['result']}): {test['control_objective']}")
    lines.extend(["", "## Business Impact Estimate (Ordinal)", ""])
    bi = payload.get("business_impact_estimate") or {}
    lines.append(f"- Total business impact score: **{bi.get('total_business_impact_score')}** (ordinal, not probability)")
    lines.append(f"- Downtime minutes (estimate): {bi.get('downtime_minutes')}")
    lines.append(f"- Affected users (estimate): {bi.get('affected_users')}")
    forum = payload.get("business_impact_forum_mapping") or {}
    if forum:
        lines.extend(
            [
                "",
                "## Business impact (forum language)",
                "",
                f"- User impact: {forum.get('user_impact')}",
                f"- Operational risk: {forum.get('operational_risk')}",
                f"- Suggested forum: {forum.get('suggested_forum')}",
            ]
        )
    lines.extend(["", "## AI usage transparency", ""])
    ai = payload.get("ai_usage_transparency") or {}
    lines.append(f"_{ai.get('human_review_required', '')}_")
    lines.append("")
    lines.append("AI may assist with:")
    for row in ai.get("ai_assists_with") or []:
        lines.append(f"- {row}")
    lines.append("")
    lines.append("AI does **not** authorize:")
    for row in ai.get("ai_does_not_authorize") or []:
        lines.append(f"- {row}")
    lines.extend(["", "## Appendix: Audit integrity verification", ""])
    appendix = (payload.get("appendix") or {}).get("audit_integrity_verification") or {}
    lines.append(f"- Verified: **{appendix.get('verified')}**")
    lines.append(f"- Procedure: {appendix.get('procedure')}")
    lines.extend(["", "## Unsafe inferences blocked", ""])
    for item in payload.get("unsafe_inferences_blocked") or []:
        lines.append(f"- {item}")
    lines.extend(["", "## Limitations and non-claims", ""])
    for lim in payload.get("limitations_and_non_claims") or payload.get("limitations") or []:
        lines.append(f"- {lim}")
    lines.extend(["", "## Recommended next actions", ""])
    for action in payload.get("recommended_next_actions") or []:
        lines.append(f"- {action}")
    return "\n".join(lines)


def _markdown_to_html(markdown: str) -> str:
    body = markdown.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    body = body.replace("\n\n", "</p><p>").replace("\n", "<br/>")
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'/>"
        "<title>Technology Risk Governance Report</title></head>"
        f"<body><p>{body}</p></body></html>"
    )

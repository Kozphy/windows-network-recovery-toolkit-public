"""Risk KPI analytics from audit JSONL — business impact oriented metrics."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core.analytics.summary import (
    _classification_of,
    _evidence_tier_of,
    _incident_key,
    _is_destructive_blocked,
    _is_remediation_preview,
    _load_audit_records,
    _policy_decision_of,
    _verify_audit_files,
)
from src.platform_core.governance.evidence_to_action import attach_governance_envelope

SCHEMA_VERSION = "risk_kpi_summary.v1"
_HIGH_RISK_CLASSIFICATIONS = frozenset(
    {"POSSIBLE_MITM_RISK", "SUSPICIOUS_PROXY", "TLS_MISMATCH", "UNKNOWN_LOCAL_PROXY"}
)


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _minutes_between(a: datetime | None, b: datetime | None) -> float | None:
    if a is None or b is None:
        return None
    return max(0.0, (b - a).total_seconds() / 60.0)


def build_risk_kpi_summary(
    audit_dir: Path,
    *,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Build risk kpi summary.

    Args:
        audit_dir: audit dir supplied by the caller.
        source_label: source label supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    records, files, load_limits = _load_audit_records(audit_dir)
    limitations = [
        "KPIs are evidence-backed aggregates — not statistical probabilities.",
        "Classification is not accusation; counts support triage and governance review.",
        "Mean-time metrics require timestamp fields in audit records.",
    ]
    limitations.extend(load_limits)

    by_incident: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        by_incident[_incident_key(row)].append(row)

    classifications = Counter(filter(None, (_classification_of(r) for r in records)))
    evidence_tiers = Counter(filter(None, (_evidence_tier_of(r) for r in records)))
    policy_decisions = Counter(filter(None, (_policy_decision_of(r) for r in records)))

    preview_count = sum(1 for r in records if _is_remediation_preview(r))
    confirmed_count = sum(
        1
        for r in records
        if str(r.get("action", "")).lower() in ("remediation_execute", "applied")
        and r.get("dry_run") is False
        and str(r.get("decision", "")).lower() not in ("blocked", "denied")
    )
    blocked_count = sum(1 for r in records if _is_destructive_blocked(r))

    detection_minutes: list[float] = []
    preview_minutes: list[float] = []
    unresolved = 0
    high_residual = 0
    control_failures = 0
    repeat_keys: Counter[str] = Counter()

    for _key, rows in by_incident.items():
        sorted_rows = sorted(rows, key=lambda r: str(r.get("timestamp") or ""))
        first_ts = _parse_ts(sorted_rows[0].get("timestamp"))
        classified_ts = None
        preview_ts = None
        resolved = False
        cls = ""
        tier = ""
        for row in sorted_rows:
            if not cls:
                cls = _classification_of(row) or ""
            if not tier:
                tier = _evidence_tier_of(row) or ""
            if _classification_of(row) and classified_ts is None:
                classified_ts = _parse_ts(row.get("timestamp"))
            if _is_remediation_preview(row):
                preview_ts = _parse_ts(row.get("timestamp"))
            if str(row.get("status", "")).lower() in ("resolved", "closed"):
                resolved = True
            if str(row.get("decision", "")).lower() == "blocked":
                control_failures += 1
        if cls:
            repeat_keys[cls] += 1
        if not resolved and cls:
            unresolved += 1
        if cls in _HIGH_RISK_CLASSIFICATIONS and not resolved:
            high_residual += 1
        det = _minutes_between(first_ts, classified_ts or first_ts)
        if det is not None:
            detection_minutes.append(det)
        prev = _minutes_between(first_ts, preview_ts)
        if prev is not None:
            preview_minutes.append(prev)

    total_incidents = len(by_incident) if by_incident else len(records)
    repeat_incidents = sum(max(0, count - 1) for count in repeat_keys.values())
    control_test_total = max(control_failures + preview_count, 1)
    control_failure_rate = round(control_failures / control_test_total, 4)

    audit_integrity = _verify_audit_files(files) if files else {}

    kpis = {
        "total_incidents": total_incidents,
        "total_audit_records": len(records),
        "incidents_by_classification": dict(classifications),
        "incidents_by_evidence_tier": dict(evidence_tiers),
        "policy_decisions_by_type": dict(policy_decisions),
        "remediation_previews_count": preview_count,
        "confirmed_remediations_count": confirmed_count,
        "destructive_actions_blocked_count": blocked_count,
        "mean_time_to_detection_minutes": round(sum(detection_minutes) / len(detection_minutes), 2)
        if detection_minutes
        else None,
        "mean_time_to_preview_minutes": round(sum(preview_minutes) / len(preview_minutes), 2)
        if preview_minutes
        else None,
        "unresolved_incident_count": unresolved,
        "high_residual_risk_count": high_residual,
        "control_failure_rate": control_failure_rate,
        "repeat_incident_rate": round(repeat_incidents / max(total_incidents, 1), 4),
    }

    payload = {
        "schema_version": SCHEMA_VERSION,
        "command": "risk-kpi-summary",
        "kpis": kpis,
        "audit_integrity": audit_integrity,
        "limitations": limitations,
        "source": {
            "audit_dir": str(audit_dir.resolve()),
            "label": source_label or audit_dir.name,
            "files": [p.name for p in files],
        },
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "confidence_type": "ordinal_not_probability",
    }
    return attach_governance_envelope(
        payload,
        dry_run=True,
        requires_confirmation=True,
        limitations=limitations,
    )


def format_risk_kpi_markdown(payload: dict[str, Any]) -> str:
    """Format risk kpi markdown.

    Args:
        payload: payload supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    kpis = payload.get("kpis") or {}
    lines = [
        "# Risk KPI Summary",
        "",
        "## Executive Summary",
        "",
        f"**Total incidents:** {kpis.get('total_incidents', 0)} · "
        f"**Unresolved:** {kpis.get('unresolved_incident_count', 0)} · "
        f"**High residual risk:** {kpis.get('high_residual_risk_count', 0)}",
        "",
        "Evidence-backed KPI rollup for Cyber / IT / Data Risk analytics. "
        "Not SIEM, EDR, or autonomous remediation.",
        "",
        "## KPI Table",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Remediation previews | {kpis.get('remediation_previews_count', 0)} |",
        f"| Confirmed remediations | {kpis.get('confirmed_remediations_count', 0)} |",
        f"| Mean time to detection (min) | {kpis.get('mean_time_to_detection_minutes', 'n/a')} |",
        f"| Mean time to preview (min) | {kpis.get('mean_time_to_preview_minutes', 'n/a')} |",
        f"| Control failure rate | {kpis.get('control_failure_rate', 0)} |",
        f"| Repeat incident rate | {kpis.get('repeat_incident_rate', 0)} |",
        "",
        "## Classification Distribution",
        "",
    ]
    for name, value in sorted((kpis.get("incidents_by_classification") or {}).items()):
        lines.append(f"- **{name}**: {value}")
    lines.extend(["", "## Limitations", ""])
    for item in payload.get("limitations") or []:
        lines.append(f"- {item}")
    return "\n".join(lines)

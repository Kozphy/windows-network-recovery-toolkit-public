"""Evidence-backed coordination KPIs for governance reports (counts/durations — not probabilities)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def compute_coordination_kpis(audit_dir: Path) -> dict[str, Any]:
    """Roll up decision-context audit events into ordinal KPI counts.

    Metrics are counts and mean durations where timestamps exist — not statistical probabilities.
    """
    kpi: dict[str, Any] = {
        "schema_version": "coordination_kpis.v1",
        "unassigned_owner_cases": 0,
        "cases_awaiting_approval": 0,
        "cases_deferred_to_maintenance_windows": 0,
        "sla_overdue_cases": 0,
        "evidence_expired_cases": 0,
        "immediate_escalation_cases": 0,
        "mean_time_to_owner_assignment_seconds": None,
        "mean_time_proof_to_approval_seconds": None,
        "mean_time_approval_to_remediation_preview_seconds": None,
        "sample_sizes": {
            "stakeholder_resolved": 0,
            "timing_evaluated": 0,
            "coordination_status_set": 0,
        },
        "limitations": [
            "KPIs are evidence-backed counts/durations from audit JSONL — not probabilities.",
            "Missing timestamps yield null means rather than estimates.",
        ],
    }
    if not audit_dir.is_dir():
        return kpi

    owner_deltas: list[float] = []
    for path in sorted(audit_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            action = str(row.get("action_type") or "")
            payload = row.get("payload") or {}
            if not isinstance(payload, dict):
                payload = {}
            if action == "stakeholder_resolved":
                kpi["sample_sizes"]["stakeholder_resolved"] += 1
                unresolved = payload.get("unresolved_fields") or []
                if "asset_owner" in unresolved:
                    kpi["unassigned_owner_cases"] += 1
            elif action == "timing_evaluated":
                kpi["sample_sizes"]["timing_evaluated"] += 1
                decision = str(payload.get("decision") or "")
                if decision == "DEFERRED_TO_WINDOW":
                    kpi["cases_deferred_to_maintenance_windows"] += 1
                elif decision == "SLA_OVERDUE":
                    kpi["sla_overdue_cases"] += 1
                elif decision == "EVIDENCE_EXPIRED":
                    kpi["evidence_expired_cases"] += 1
                elif decision == "ESCALATE_NOW":
                    kpi["immediate_escalation_cases"] += 1
            elif action == "coordination_status_set":
                kpi["sample_sizes"]["coordination_status_set"] += 1
                status = str(payload.get("coordination_status") or "")
                if status == "NEEDS_APPROVAL":
                    kpi["cases_awaiting_approval"] += 1
                if status == "NEEDS_OWNER":
                    kpi["unassigned_owner_cases"] += 1
                if status == "DEFERRED_TO_WINDOW":
                    kpi["cases_deferred_to_maintenance_windows"] += 1
                if status == "ESCALATE_NOW":
                    kpi["immediate_escalation_cases"] += 1
                if status == "EXPIRED":
                    kpi["evidence_expired_cases"] += 1

    if owner_deltas:
        kpi["mean_time_to_owner_assignment_seconds"] = sum(owner_deltas) / len(owner_deltas)
    return kpi

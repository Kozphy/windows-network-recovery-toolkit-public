"""Technology risk reporting — JSON, CSV, and executive report exports.

Module responsibility:
    Transform ``analytics_pipeline`` payloads into committee-ready artefacts:
    executive JSON, risk_scores files, and Power BI-compatible CSV (via delegate).

System placement:
    Used by ``backend/technology_risk_routes`` (``GET /reports/executive``) and optional
  CLI/export workflows. Does not collect evidence or mutate host state.

Key invariants:
    * Read-only over input payload except when writing export files.
    * ``attach_risk_scores`` is idempotent when ``risk_scores`` already present.
    * Executive report schema version: ``technology_risk_executive_report.v1``.

Side effects:
    ``export_technology_risk_report`` writes files under ``out_dir`` (creates directory).

Idempotency:
    ``attach_risk_scores``: safe to call multiple times on same payload.
    File export overwrites paths returned in the result dict.

Failure modes:
    Missing ``incidents`` yields empty risk_scores and zeroed executive summary counts.
    Circular import avoided: lazy import of ``score_risk_from_incident`` in attach path.

Audit Notes:
    * Export writes local files only — verify ``out_dir`` before sharing externally.
    * Executive report includes governance_principles; do not strip limitations for dashboards.
    * Recovery: re-run ``run_endpoint_analytics_pipeline`` from fresh audit JSONL.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from windows_network_toolkit.analytics_pipeline import export_endpoint_analytics


def attach_risk_scores(payload: dict[str, Any]) -> dict[str, Any]:
    """Add ``risk_scores[]`` to an analytics pipeline payload (shallow copy).

    Args:
        payload: Output of ``run_endpoint_analytics_pipeline``; may already contain
            ``risk_scores`` from pipeline (returns copy unchanged).

    Returns:
        New dict with ``risk_scores`` list — one entry per incident with ``incident_id``.

    Side effects:
        None.

    Idempotency:
        Returns shallow copy without recomputation when ``risk_scores`` key is truthy.
    """
    if payload.get("risk_scores"):
        return dict(payload)
    from windows_network_toolkit.risk_scoring_engine import score_risk_from_incident

    out = dict(payload)
    controls = out.get("control_tests") or []
    scores = []
    for incident in out.get("incidents") or []:
        result = score_risk_from_incident(incident, control_tests=controls)
        row = result.to_dict()
        row["incident_id"] = incident.get("incident_id")
        scores.append(row)
    out["risk_scores"] = scores
    return out


def build_executive_report(payload: dict[str, Any]) -> dict[str, Any]:
    """Build executive JSON report from an analytics pipeline payload.

    Args:
        payload: Analytics pipeline dict with incidents, control_tests, dashboard_dataset.

    Returns:
        Dict with schema_version ``technology_risk_executive_report.v1``, executive_summary
        KPIs, governance_principles, full incidents/risk_scores/control_tests, and limitations.

    Side effects:
        None.

    Audit Notes:
        Positioning string states platform is not antivirus/EDR/autonomous remediation.
        ``human_review_recommended`` count derived from risk_scores — verify before action.
    """
    enriched = attach_risk_scores(payload)
    dash = enriched.get("dashboard_dataset") or {}
    summary = dash.get("summary") or {}
    incidents = enriched.get("incidents") or []
    controls = enriched.get("control_tests") or []
    risk_scores = enriched.get("risk_scores") or []

    high_risk = [r for r in risk_scores if r.get("risk_level") == "HIGH"]
    control_failures = [c for c in controls if c.get("test_result") == "FAIL"]
    human_review = [r for r in risk_scores if r.get("human_review_recommended")]

    return {
        "schema_version": "technology_risk_executive_report.v1",
        "executive_summary": {
            "total_incidents": summary.get("total_incidents", len(incidents)),
            "high_risk_incidents": summary.get("high_risk_incidents", len(high_risk)),
            "control_failures": summary.get("control_failures", len(control_failures)),
            "human_review_recommended": len(human_review),
            "reverter_suspected_count": summary.get("reverter_suspected_count", 0),
        },
        "positioning": (
            "Technology Risk & Control Analytics — not antivirus, EDR, XDR, "
            "malware detection, or autonomous remediation."
        ),
        "governance_principles": [
            "Observation is not proof.",
            "Correlation is not causation.",
            "Confidence is not certainty.",
            "Classification is not accusation.",
            "Policy permission is not safety guarantee.",
        ],
        "incidents": incidents,
        "risk_scores": risk_scores,
        "control_tests": controls,
        "dashboard_kpis": summary,
        "limitations": list(enriched.get("limitations") or []),
        "recommended_actions": [
            "Route HIGH risk and human_review_recommended items to analyst queue.",
            "Run proxy-health and proxy-watch before any preview remediation.",
            "Export CSV artefacts for Power BI committee dashboards.",
            "Collect T4 writer proof (Sysmon E13 / Procmon) before escalation.",
        ],
    }


def export_technology_risk_report(
    payload: dict[str, Any],
    out_dir: Path,
    *,
    export_csv: bool = True,
) -> dict[str, str]:
    """Write JSON exports (incidents, risks, controls) and Power BI-ready CSV.

    Args:
        payload: Analytics pipeline payload (enriched with risk scores).
        out_dir: Destination directory; created if missing.
        export_csv: When True, delegate CSV chart exports and write ``risk_scores.csv``.

    Returns:
        Map of artefact filename → absolute path string.

    Side effects:
        Creates ``out_dir`` and overwrites existing export files with same names.

    Idempotency:
        Re-running overwrites files deterministically from the same payload.

    Audit Notes:
        * Writes local filesystem only — no audit JSONL append.
        * Review ``limitations`` in executive_report.json before external distribution.
    """
    enriched = attach_risk_scores(payload)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = export_endpoint_analytics(enriched, out_dir, export_csv=export_csv)

    executive = build_executive_report(enriched)
    exec_path = out_dir / "executive_report.json"
    exec_path.write_text(json.dumps(executive, indent=2, ensure_ascii=False), encoding="utf-8")
    paths["executive_report.json"] = str(exec_path.resolve())

    risks_path = out_dir / "risk_scores.json"
    risks_path.write_text(
        json.dumps(enriched.get("risk_scores") or [], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    paths["risk_scores.json"] = str(risks_path.resolve())

    if export_csv and enriched.get("risk_scores"):
        import csv

        csv_path = out_dir / "risk_scores.csv"
        rows = enriched["risk_scores"]
        fieldnames = sorted({k for row in rows for k in row})
        with csv_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        paths["risk_scores.csv"] = str(csv_path.resolve())

    return paths

"""Risk matrix builder — ordinal heat-map rows from risk register fixtures."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope

SCHEMA_VERSION = "risk_matrix.v1"

DEFAULT_REGISTER_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "fixtures"
    / "risk_register"
    / "sample_risk_register.json"
)

_MATRIX_LIMITATIONS = [
    "Probability and impact scores are ordinal (1–5), not statistical frequencies.",
    "Severity score is likelihood × impact for heat-map sorting — not financial loss.",
    "Evidence tier describes observation strength — observation is not proof.",
    "Recommended control is governance guidance — recommendation is not execution.",
]

_CONTROL_BY_RISK_PREFIX: dict[str, str] = {
    "RISK-001": "CTRL-001",
    "RISK-002": "CTRL-004",
    "RISK-003": "CTRL-008",
}


def default_risk_register_path() -> Path:
    """Return default risk register path.

    Returns:
        The computed `Path` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return DEFAULT_REGISTER_PATH


def load_risk_register(path: Path | str | None = None) -> dict[str, Any]:
    """Load a ``risk_register.v1`` JSON document."""
    register_path = Path(path) if path else DEFAULT_REGISTER_PATH
    if not register_path.is_file():
        raise FileNotFoundError(f"Risk register not found: {register_path}")
    return json.loads(register_path.read_text(encoding="utf-8"))


def _infer_category(risk: dict[str, Any]) -> str:
    if risk.get("risk_category"):
        return str(risk["risk_category"])
    title = f"{risk.get('risk_title', '')} {risk.get('asset_or_process', '')}".lower()
    if any(token in title for token in ("proxy", "wininet", "browser", "endpoint")):
        return "Endpoint Reliability"
    if any(token in title for token in ("tls", "https", "certificate", "mitm")):
        return "Technology Risk"
    if any(token in title for token in ("cloud", "azure", "gcp", "cost", "budget")):
        return "FinOps"
    if any(token in title for token in ("audit", "governance", "control")):
        return "Cloud Governance"
    return "Technology Risk"


def _infer_evidence_tier(risk: dict[str, Any]) -> str:
    if risk.get("evidence_tier"):
        return str(risk["evidence_tier"])
    sources = [str(s).lower() for s in risk.get("evidence_sources") or []]
    if any("sysmon" in s or "writer" in s for s in sources):
        return "T2_RUNTIME_CORROBORATION"
    if any("tls-proof" in s or "path contrast" in s for s in sources):
        return "T2_RUNTIME_CORROBORATION"
    if any("audit" in s for s in sources):
        return "T1_LOCAL_CONFIG_EVIDENCE"
    return "T1_LOCAL_CONFIG_EVIDENCE"


def _confidence_score(risk: dict[str, Any]) -> float:
    if risk.get("confidence") is not None:
        return round(max(0.0, min(1.0, float(risk["confidence"]))), 2)
    effectiveness = str(risk.get("control_effectiveness", "partial")).lower()
    mapping = {"strong": 0.8, "partial": 0.55, "weak": 0.35, "none": 0.25}
    return mapping.get(effectiveness, 0.5)


def _recommended_control(risk: dict[str, Any]) -> str:
    if risk.get("recommended_control"):
        return str(risk["recommended_control"])
    risk_id = str(risk.get("risk_id", ""))
    return _CONTROL_BY_RISK_PREFIX.get(risk_id, "CTRL-010")


def _business_explanation(risk: dict[str, Any]) -> str:
    if risk.get("business_explanation"):
        return str(risk["business_explanation"])
    title = risk.get("risk_title") or "Technology risk"
    impact = risk.get("inherent_risk") or "medium"
    return (
        f"{title} may disrupt user productivity and audit evidence quality. "
        f"Inherent risk band: {impact}. Review with limitations before escalation."
    )


def build_risk_matrix_row(risk: dict[str, Any]) -> dict[str, Any]:
    """Build one heat-map row from a risk register entry."""
    probability = int(risk.get("probability_score") or risk.get("likelihood_score") or 3)
    impact = int(risk.get("impact_score") or 3)
    probability = max(1, min(5, probability))
    impact = max(1, min(5, impact))
    category = _infer_category(risk)
    return {
        "risk_id": str(risk.get("risk_id") or ""),
        "risk_description": str(
            risk.get("risk_description")
            or risk.get("risk_scenario")
            or risk.get("risk_title")
            or ""
        ),
        "risk_category": category,
        "category": category,
        "probability_score": probability,
        "impact_score": impact,
        "severity_score": probability * impact,
        "confidence": _confidence_score(risk),
        "evidence_tier": _infer_evidence_tier(risk),
        "recommended_control": _recommended_control(risk),
        "recommended_action": str(
            risk.get("recommended_action")
            or risk.get("remediation_action")
            or "Observe and collect additional evidence"
        ),
        "business_explanation": _business_explanation(risk),
        "risk_owner": str(risk.get("risk_owner") or ""),
        "status": str(risk.get("status") or "open"),
        "due_date": str(risk.get("due_date") or ""),
    }


def build_risk_matrix(
    *,
    register_path: Path | str | None = None,
    register: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ``risk_matrix.v1`` payload with governance envelope."""
    data = register if register is not None else load_risk_register(register_path)
    rows = [build_risk_matrix_row(risk) for risk in data.get("risks") or []]
    high_severity = [r for r in rows if r["severity_score"] >= 12]
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_schema": data.get("schema_version", "risk_register.v1"),
        "matrix_rows": rows,
        "heatmap": rows,
        "summary": {
            "total_risks": len(rows),
            "open_risks": sum(1 for r in rows if r.get("status") == "open"),
            "high_severity_count": len(high_severity),
            "max_severity_score": max((r["severity_score"] for r in rows), default=0),
        },
        "limitations": list(data.get("limitations") or []) + _MATRIX_LIMITATIONS,
    }
    return attach_governance_envelope(payload, limitations=payload["limitations"])


def write_risk_matrix_csv(rows: list[dict[str, Any]], out_path: Path) -> None:
    """Write heat-map rows to CSV."""
    columns = [
        "risk_id",
        "risk_description",
        "risk_category",
        "category",
        "probability_score",
        "impact_score",
        "severity_score",
        "confidence",
        "evidence_tier",
        "recommended_control",
        "recommended_action",
        "business_explanation",
        "risk_owner",
        "status",
        "due_date",
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def export_risk_matrix(
    *,
    register_path: Path | str | None = None,
    out_path: Path | None = None,
    fmt: str = "json",
) -> dict[str, Any]:
    """Export risk matrix as JSON or CSV."""
    payload = build_risk_matrix(register_path=register_path)
    rows = payload["matrix_rows"]
    if fmt == "csv":
        if out_path is None:
            raise ValueError("CSV export requires --out path")
        write_risk_matrix_csv(rows, out_path)
        payload["export_path"] = str(out_path.resolve())
        payload["export_format"] = "csv"
        return payload
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        payload["export_path"] = str(out_path.resolve())
    payload["export_format"] = "json"
    return payload

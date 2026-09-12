"""Sequential deterministic orchestrator — maps pipeline output to agent contracts.

Module responsibility:
    Wraps ``run_endpoint_analytics_pipeline`` and ``build_executive_report`` and projects
    their outputs into the typed agent-contract bundle used by the platform API and
    reporting layer: ``EvidenceAgentOutput``, ``ClassificationAgentOutput``,
    ``RootCauseAgentOutput``, ``RiskAssessmentAgentOutput``,
    ``ControlValidationAgentOutput``, and ``ReportingAgentOutput``.  Execution is
    single-pass and fully deterministic from the supplied ``fixture`` dict; no live
    collection or side effects occur.

Typical usage:
    bundle = run_deterministic_orchestration(fixture=loaded_evidence_dict)

Limitations:
    - Returns ``{"error": "no_incident"}`` when the pipeline produces no incidents;
      callers must handle this sentinel.
    - Risk score and level are derived from classification confidence only; they are
      ordinal estimates, not calibrated probabilities.
"""

from __future__ import annotations

from typing import Any

from src.platform_core.agents.contracts import (
    ClassificationAgentOutput,
    ControlValidationAgentOutput,
    EvidenceAgentOutput,
    ReportingAgentOutput,
    RiskAssessmentAgentOutput,
    RootCauseAgentOutput,
)
from windows_network_toolkit.analytics_pipeline import run_endpoint_analytics_pipeline
from windows_network_toolkit.reporting import build_executive_report


def run_deterministic_orchestration(
    fixture: dict[str, Any],
) -> dict[str, Any]:
    """Run existing pipeline and return agent contract bundle."""
    endpoint_id = str(fixture.get("endpoint_id") or "ep-unknown")
    evidence = EvidenceAgentOutput(
        event_id="pending",
        endpoint_id=endpoint_id,
        evidence_type="proxy_state",
        raw_snapshot=fixture,
        limitations=["Collector output — observation not proof."],
    )

    payload = run_endpoint_analytics_pipeline(fixture=fixture)
    incidents = payload.get("incidents") or []
    if not incidents:
        return {"evidence": evidence.model_dump(), "error": "no_incident"}

    inc = incidents[0]
    incident_id = str(inc.get("incident_id") or "INC-UNKNOWN")
    classification = ClassificationAgentOutput(
        incident_id=incident_id,
        primary_classification=str(
            inc.get("incident_class") or inc.get("primary_classification") or "UNKNOWN"
        ),
        proof_tier=str(inc.get("proof_tier") or inc.get("evidence_tier") or "T1_STATE_EVIDENCE"),
        confidence=float(inc.get("confidence") or 0.5),
        secondary_signals=list(inc.get("secondary_signals") or []),
        limitations=list(inc.get("limitations") or []),
    )

    root_cause = RootCauseAgentOutput(
        incident_id=incident_id,
        hypotheses=[
            {
                "label": classification.primary_classification,
                "confidence_ordinal": "medium" if classification.confidence > 0.5 else "low",
            }
        ],
        limitations=classification.limitations + ["Hypothesis is triage — not causation proof."],
    )

    conf = classification.confidence
    risk = RiskAssessmentAgentOutput(
        incident_id=incident_id,
        risk_score=min(100.0, conf * 100),
        risk_level="MEDIUM" if conf > 0.5 else "LOW",
        human_review_recommended=conf > 0.7,
        limitations=["Ordinal score — not calibrated probability."],
    )

    controls_raw = [
        c for c in (payload.get("control_tests") or []) if c.get("incident_id") == incident_id
    ]
    if not controls_raw:
        controls_raw = payload.get("control_tests") or []
    controls = ControlValidationAgentOutput(
        incident_id=incident_id,
        control_tests=controls_raw,
        limitations=["Control PASS does not guarantee production safety."],
    )

    exec_report = build_executive_report(payload)
    reporting = ReportingAgentOutput(
        kpis={k: exec_report.get(k) for k in list(exec_report.keys())[:8]},
        limitations=["Management information — not formal audit opinion."],
    )

    return {
        "evidence": evidence.model_dump(),
        "classification": classification.model_dump(),
        "root_cause": root_cause.model_dump(),
        "risk": risk.model_dump(),
        "controls": controls.model_dump(),
        "reporting": reporting.model_dump(),
    }

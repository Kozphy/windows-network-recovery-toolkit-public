"""Governance decision and management reporting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from src.platform_core.governance.proof_tier import resolve_proof_tier
from src.platform_core.governance.report_sections import (
    AI_TRANSPARENCY_SECTION,
    GOVERNANCE_PRINCIPLES,
    NON_CLAIMS,
)
from src.platform_core.governance.risk_decision_record import build_risk_decision_record
from src.platform_core.risk.business_impact_mapping import map_business_impact
from src.platform_core.risk.control_test_mature import run_mature_control_tests

from .asset import asset_for_fixture
from .business_objective import objective_for_fixture
from .control import controls_for_fixture
from .control_test import run_control_tests
from .finding import findings_from_fixture
from .risk_rating import rate_risk
from .threat import threat_for_fixture


class GovernanceDecision(BaseModel):
    """Represent the governance decision type.

    Key fields:
        decision_id: Structured value carried by this type.
        outcome: Structured value carried by this type.
        dry_run: Structured value carried by this type.
        requires_typed_confirmation: Structured value carried by this type.
        rollback_plan_required: Structured value carried by this type.
        audit_logging_required: Structured value carried by this type.
        recommended_action: Structured value carried by this type.
        governance_owner: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    decision_id: str
    outcome: str
    dry_run: bool = True
    requires_typed_confirmation: bool = True
    rollback_plan_required: bool = True
    audit_logging_required: bool = True
    recommended_action: str
    governance_owner: str = "IT Governance"
    limitations: list[str] = Field(default_factory=list)


def load_fixture(path: Path) -> dict[str, Any]:
    """Load fixture.

    Args:
        path: path supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        Reads data from the requested source.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def _governance_decision(fixture: dict[str, Any]) -> GovernanceDecision:
    policy = fixture.get("policy_decision") or {}
    dry_run = bool(fixture.get("dry_run", True) or policy.get("dry_run", True))
    outcome = policy.get("outcome", "PREVIEW_ONLY")
    classification = (fixture.get("classification") or {}).get("primary_classification", "")
    action = policy.get("action") or f"Preview remediation for {classification}"
    return GovernanceDecision(
        decision_id="GOV_001",
        outcome=outcome,
        dry_run=dry_run,
        requires_typed_confirmation=bool(policy.get("requires_confirmation", True)),
        rollback_plan_required=bool(fixture.get("rollback_plan_present", True)),
        audit_logging_required=bool(policy.get("audit_logging", True)),
        recommended_action=action,
        governance_owner="IT Operations / IT Governance",
        limitations=[
            "Not autonomous remediation — human approval required for apply.",
            "Policy permission does not guarantee operational safety.",
            "Does not claim malware detection or EDR-grade verdicts.",
        ],
    )


def assess_risk(fixture: dict[str, Any]) -> dict[str, Any]:
    """Return assess risk.

    Args:
        fixture: fixture supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    tests = run_control_tests(fixture)
    mature_tests = run_mature_control_tests(fixture)
    findings = findings_from_fixture(fixture, tests)
    rating = rate_risk(findings, tests, fixture)
    decision_record = build_risk_decision_record(fixture)
    proof_tier_result = resolve_proof_tier(fixture)
    impact_map = map_business_impact(
        str((fixture.get("classification") or {}).get("primary_classification") or "")
    )
    result = {
        "schema_version": "technology_risk_decision.v1",
        "command": "risk-assess",
        "case_id": fixture.get("case_id"),
        "risk_decision_record": decision_record.model_dump(mode="json"),
        "proof_tier": proof_tier_result.model_dump(),
        "business_impact_forum": impact_map.model_dump(),
        "mature_control_tests": [t.model_dump() for t in mature_tests],
        "business_objective": objective_for_fixture(fixture).model_dump(),
        "asset": asset_for_fixture(fixture).model_dump(),
        "threat": threat_for_fixture(fixture).model_dump(),
        "controls": [c.model_dump() for c in controls_for_fixture(fixture)],
        "findings": [f.model_dump() for f in findings],
        "risk_rating": rating.model_dump(),
        "governance_decision": _governance_decision(fixture).model_dump(),
        "limitations": rating.limitations,
        "disclaimer": (
            "Technology risk assessment for governance support — not antivirus, EDR, or XDR. "
            "Observation ≠ proof; correlation ≠ causation."
        ),
    }
    classification = (fixture.get("classification") or {}).get("primary_classification")
    policy = fixture.get("policy_decision") or {}
    proof_block = fixture.get("proof") or {}
    conclusion = proof_block.get("conclusion") if isinstance(proof_block, dict) else {}
    evidence_tier = proof_tier_result.proof_tier.value
    return attach_governance_envelope(
        result,
        primary_classification=classification,
        evidence_tier=evidence_tier,
        proof_conclusion=conclusion.get("status") if isinstance(conclusion, dict) else None,
        policy_outcome=policy.get("outcome"),
        dry_run=bool(fixture.get("dry_run", True) or policy.get("dry_run", True)),
        requires_confirmation=bool(policy.get("requires_confirmation", True)),
    )


def build_governance_report(
    fixture: dict[str, Any], *, format: str = "json"
) -> str | dict[str, Any]:
    """Build governance report.

    Args:
        fixture: fixture supplied by the caller.
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
    assessment = assess_risk(fixture)
    tests = run_control_tests(fixture)
    mature = run_mature_control_tests(fixture)
    assessment["control_tests"] = [t.model_dump() for t in tests]
    assessment["mature_control_tests"] = [t.model_dump() for t in mature]

    # Optional decision-context enrichment (does not alter technical proof fields).
    decision_context = fixture.get("decision_context")
    if not decision_context and fixture.get("include_decision_context"):
        from src.platform_core.decision_context import build_decision_envelope

        policy = fixture.get("policy_decision") or {}
        classification = (fixture.get("classification") or {}).get("primary_classification", "")
        envelope = build_decision_envelope(
            case_id=str(fixture.get("case_id") or "gov-case"),
            classification=str(classification),
            policy_decision=str(policy.get("outcome") or "PREVIEW_ONLY"),
            policy_allowed=bool(policy.get("allowed", False)),
            policy_requires_approval=bool(policy.get("requires_confirmation", True)),
            proof_result=fixture.get("proof") if isinstance(fixture.get("proof"), dict) else {},
            write_audit=False,
            timezone_name=fixture.get("timezone"),
            stakeholder_config=fixture.get("stakeholder_config"),
            timing_config=fixture.get("timing_config"),
        )
        decision_context = envelope.to_dict()
    if decision_context:
        assessment["decision_context"] = decision_context
        assessment["coordination_status"] = decision_context.get("coordination_status")
        assessment["policy_decision_separate"] = decision_context.get("policy_decision")
        assessment["governance_principles"] = list(GOVERNANCE_PRINCIPLES)

    from src.platform_core.governance.coordination_kpis import compute_coordination_kpis

    audit_dir = fixture.get("audit_dir")
    if audit_dir:
        assessment["coordination_kpis"] = compute_coordination_kpis(Path(audit_dir))

    if format == "json":
        return assessment

    obj = assessment["business_objective"]
    asset = assessment["asset"]
    threat = assessment["threat"]
    rating = assessment["risk_rating"]
    gov = assessment["governance_decision"]
    findings = assessment["findings"]
    rdr = assessment.get("risk_decision_record") or {}
    proof = assessment.get("proof_tier") or {}
    dc = assessment.get("decision_context") or {}

    lines = [
        "# Technology Risk & Control Governance Report",
        "",
        f"**Case ID:** {fixture.get('case_id', 'N/A')}",
        f"**Schema:** {assessment['schema_version']}",
        "",
        "## Executive Summary",
        "",
        assessment["disclaimer"],
        "",
        f"**Proof tier:** {rdr.get('proof_tier', proof.get('proof_tier', 'n/a'))} — "
        f"**Risk rating:** {rdr.get('risk_rating', rating.get('residual_level'))}",
        "",
        rating["summary"],
        "",
        "## 1. Technical evidence",
        "",
        "- Bundle / case references under findings and proof tier sections.",
        "",
        "## 2. Hypothesis and proof status",
        "",
        f"- Classification: {rdr.get('classification')}",
        f"- Proof tier: {rdr.get('proof_tier', proof.get('proof_tier'))}",
        f"- Human review required: {rdr.get('human_review_required')}",
        "",
        "## 3. Policy decision",
        "",
        f"- Outcome: **{gov['outcome']}** (dry-run={gov['dry_run']})",
        "",
        "## 4. Stakeholder ownership",
        "",
    ]
    sh = dc.get("stakeholder") or {}
    if sh:
        ao = (sh.get("asset_owner") or {}).get("display_name") or "(unresolved)"
        lines.append(f"- Asset owner role: {ao}")
        lines.append(
            f"- Unresolved fields: {', '.join(sh.get('unresolved_fields') or []) or 'none'}"
        )
    else:
        lines.append("- Decision context not supplied for this fixture.")
    lines.extend(
        [
            "",
            "## 5. Approval and execution authority",
            "",
            f"- Approver roles: {len(sh.get('approver_roles') or [])}",
            f"- Execution authority present: {bool(sh.get('execution_authority'))}",
            f"- Coordination status: {dc.get('coordination_status', 'n/a')}",
            "",
            "## 6. Timing, SLA and evidence validity",
            "",
        ]
    )
    tm = dc.get("timing") or {}
    if tm:
        lines.append(f"- Timing decision: {tm.get('decision')}")
        lines.append(f"- SLA due (UTC): {tm.get('sla_due_utc')}")
        lines.append(f"- Evidence expires (UTC): {tm.get('evidence_expires_utc')}")
        lines.append(f"- Timezone: {tm.get('timezone')}")
    else:
        lines.append("- Timing context not supplied.")
    lines.extend(
        [
            "",
            "## 7. Coordination status",
            "",
            f"- **{dc.get('coordination_status', 'n/a')}** (separate from policy decision)",
            "",
            "## 8. Remediation preview",
            "",
            f"- {gov['recommended_action']}",
            f"- Preview/dry-run default: **{gov['dry_run']}**",
            "",
            "## 9. Residual risk",
            "",
            f"- Residual level: {rating.get('residual_level')}",
            "",
            "## 10. Audit integrity",
            "",
            "- Use `audit verify` to validate the hash chain; this report does not rewrite logs.",
            "",
            "## Risk Decision Record",
            "",
            f"- Incident: {rdr.get('incident_id')}",
            f"- Evidence hash: `{rdr.get('evidence_hash', '')[:16]}...`",
            "",
            "## Business Objective",
            "",
            f"- **{obj['name']}** — {obj['description']}",
            f"- Owner: {obj['owner']}",
            "",
            "## Asset & Threat",
            "",
            f"- **Asset:** {asset['name']} ({asset['asset_type']})",
            f"- **Threat:** {threat['name']} — {threat['failure_mode']}",
            "",
            "## Findings",
            "",
        ]
    )
    for f in findings:
        lines.append(
            f"- **{f['title']}** ({f['classification']}) — tier: {f['evidence_tier']}, "
            f"confidence: {f['confidence']}"
        )
    lines.extend(
        [
            "",
            "## Risk Rating",
            "",
            "| Inherent | Residual | Likelihood | Impact | Control effectiveness |",
            "|----------|----------|------------|--------|----------------------|",
            f"| {rating['inherent_level']} | {rating['residual_level']} | {rating['likelihood']} | "
            f"{rating['impact']} | {rating['control_effectiveness']} |",
            "",
            "## Control Test Results",
            "",
        ]
    )
    for t in tests:
        lines.append(f"- **{t.control_name}**: {t.result.value} — {t.finding_summary}")
    lines.extend(["", "## Mature control tests", ""])
    for mt in mature:
        lines.append(f"- **{mt.control_name}** ({mt.test_result.value}): {mt.control_objective}")
    if assessment.get("coordination_kpis"):
        k = assessment["coordination_kpis"]
        lines.extend(
            [
                "",
                "## Coordination KPIs (counts — not probabilities)",
                "",
                f"- Unassigned owner cases: {k.get('unassigned_owner_cases')}",
                f"- Awaiting approval: {k.get('cases_awaiting_approval')}",
                f"- Deferred to maintenance windows: {k.get('cases_deferred_to_maintenance_windows')}",
                f"- SLA overdue: {k.get('sla_overdue_cases')}",
                f"- Evidence expired: {k.get('evidence_expired_cases')}",
                f"- Immediate escalation: {k.get('immediate_escalation_cases')}",
            ]
        )
    lines.extend(
        [
            "",
            "## AI usage transparency",
            "",
            AI_TRANSPARENCY_SECTION["human_review_required"],
            "",
            "## Governance Decision",
            "",
            f"- Outcome: **{gov['outcome']}**",
            f"- Dry-run: **{gov['dry_run']}**",
            f"- Recommended action: {gov['recommended_action']}",
            f"- Owner: {gov['governance_owner']}",
            "",
            "## Principles",
            "",
        ]
    )
    for p in GOVERNANCE_PRINCIPLES:
        lines.append(f"- {p}")
    lines.extend(["", "## Limitations", ""])
    for lim in assessment.get("limitations", []):
        lines.append(f"- {lim}")
    lines.extend(["", "## Non-claims", ""])
    for lim in NON_CLAIMS:
        lines.append(f"- {lim}")
    return "\n".join(lines)

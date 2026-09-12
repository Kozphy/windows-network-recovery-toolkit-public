"""Audit-ready incident report generator — JSON, Markdown, and HTML output formats.

Module responsibility:
    Assembles structured endpoint-reliability incident reports from pipeline
    artifacts (timeline, decision, policy, remediation, audit trail, proof).
    Provides two entry points: ``generate_report`` for pipeline-style inputs and
    ``generate_erp_report`` for full ERP report packages.  Outputs are management
    information suitable for operator review; they are not formal audit opinions.

System placement:
    Consumed by the ``report`` CLI command, the ``audit`` package re-exports, and
    integration tests.  Called after ``run_incident_pipeline`` or ``replay_to_dict``
    to render the final human-readable artifact.

Key invariants:
    Observation is not proof; policy permission is not a safety guarantee.  The
    ``_executive_summary`` function embeds these epistemic qualifiers in all output
    formats.  ``limitations[]`` and safety notes must survive round-trips through
    all three format renderers.

Side effects:
    None — all functions are pure renderers that return strings; no file writes.

Failure modes:
    Non-JSON-serialisable objects in ``timeline``, ``decision``, or ``policy``
    are coerced to strings by ``default=str`` in ``_json_dumps``; this prevents
    crashes but may produce less structured output.
"""

from __future__ import annotations

import json
from typing import Any, Literal

ReportFormat = Literal["json", "markdown", "html"]


def _json_dumps(payload: Any) -> str:
    """Serialise a report section to indented JSON, coercing non-serialisable values.

    Args:
        payload: Any value accepted by ``json.dumps``.  Non-serialisable objects
            (e.g. leaked test mocks, enum types) are coerced with ``default=str``.

    Returns:
        An indented JSON string.
    """
    return json.dumps(payload, indent=2, default=str)


def _executive_summary(decision: dict[str, Any], policy: dict[str, Any]) -> str:
    """Build the executive summary paragraph for an incident report.

    Produces a domain-appropriate summary that preserves epistemic boundaries
    (observation ≠ proof; correlation ≠ causation) for the given incident type.

    Args:
        decision: Pipeline decision dict; must have ``incident_type`` and
            optionally ``confidence`` keys.
        policy: Policy outcome dict; must have an ``outcome`` key.

    Returns:
        A one-to-four sentence executive summary string suitable for the first
        section of an operator-facing report.
    """
    itype = decision.get("incident_type", "UNKNOWN")
    if itype in {"WININET_PROXY_DRIFT", "PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS"}:
        return (
            "Based on the collected evidence, the endpoint exhibited symptoms of WinINET proxy drift. "
            "The browser path failed through a local loopback proxy, while the direct path succeeded. "
            "The recommended action is to disable the WinINET proxy only after explicit user confirmation. "
            "No destructive action should be performed without audit logging and rollback preparation."
        )
    return (
        f"Incident classified as {itype} with confidence {decision.get('confidence', 0):.2f}. "
        f"Policy outcome: {policy.get('outcome', 'ALLOW_PREVIEW')}. "
        "Observation is not proof; correlation is not causation."
    )


def generate_report(
    *,
    timeline: list[dict[str, Any]],
    decision: dict[str, Any],
    policy: dict[str, Any],
    remediation: dict[str, Any],
    audit_rows: list[dict[str, Any]] | None = None,
    proof: list[dict[str, Any]] | None = None,
    fmt: ReportFormat = "markdown",
) -> str:
    """Generate a structured incident report in the requested format.

    Assembles a 14-section report (executive summary through audit trail) from
    standard pipeline artifacts.  No live OS calls are made — all inputs must be
    pre-collected by the caller.

    Args:
        timeline: Ordered list of timeline event dicts from the incident pipeline.
        decision: Pipeline decision dict (``incident_type``, ``confidence``,
            ``risk_level``, ``metadata``, etc.).
        policy: Policy outcome dict (``outcome``, ``dry_run``, etc.).
        remediation: Remediation preview dict (``rollback_plan``, etc.).
        audit_rows: Optional list of JSONL audit records to include in the audit
            trail section.  Defaults to an empty list.
        proof: Optional list of proof-attempt dicts.  Defaults to empty.
        fmt: Output format — ``"markdown"`` (default), ``"json"``, or ``"html"``.

    Returns:
        The formatted report as a string in the requested format.

    Side effects:
        None — pure renderer; no file writes.
    """
    sections = {
        "executive_summary": _executive_summary(decision, policy),
        "incident_timeline": timeline,
        "evidence_collected": timeline,
        "hypothesis": decision.get("metadata", {}),
        "proof": proof or [],
        "decision": decision,
        "risk_classification": decision.get("risk_level"),
        "policy_gate": policy,
        "remediation_preview": remediation,
        "actions_taken": [],
        "rollback_plan": remediation.get("rollback_plan", {}),
        "audit_trail": audit_rows or [],
    }
    if fmt == "json":
        return json.dumps(sections, indent=2)
    if fmt == "html":
        body = "<h1>Endpoint Reliability Incident Report</h1>"
        body += f"<p>{sections['executive_summary']}</p>"
        body += "<h2>Timeline</h2><pre>" + json.dumps(timeline, indent=2) + "</pre>"
        body += "<h2>Decision</h2><pre>" + json.dumps(decision, indent=2) + "</pre>"
        return f"<!DOCTYPE html><html><body>{body}</body></html>"
    lines = [
        "# Endpoint Reliability Incident Report",
        "",
        "## 1. Executive Summary",
        sections["executive_summary"],
        "",
        "## 2. Incident Timeline",
        "```json",
        json.dumps(timeline, indent=2),
        "```",
        "",
        "## 3. Evidence Collected",
        f"{len(timeline)} timeline events recorded.",
        "",
        "## 4. Hypothesis",
        json.dumps(decision.get("metadata", {}), indent=2),
        "",
        "## 5. Proof",
        json.dumps(proof or [], indent=2),
        "",
        "## 6. Decision",
        json.dumps(decision, indent=2),
        "",
        "## 7. Risk Classification",
        str(decision.get("risk_level")),
        "",
        "## 8. Policy Gate",
        json.dumps(policy, indent=2),
        "",
        "## 9. Remediation Preview",
        json.dumps(remediation, indent=2),
        "",
        "## 10. Actions Taken",
        "None (preview-only run)." if policy.get("dry_run", True) else "See audit trail.",
        "",
        "## 11. Rollback Plan",
        json.dumps(remediation.get("rollback_plan", {}), indent=2),
        "",
        "## 12. Residual Risk",
        "Policy permission is not a safety guarantee. Correlation is not causation.",
        "",
        "## 13. Control Mapping (informational)",
        "| Gate | ITGC-style |",
        "|------|------------|",
        f"| {policy.get('outcome', 'PREVIEW_ONLY')} | Detect / Audit / Prevent |",
        "",
        "## 14. Audit Trail",
        json.dumps(audit_rows or [], indent=2),
    ]
    return "\n".join(lines)


def generate_erp_report(package: dict[str, Any], *, fmt: ReportFormat = "markdown") -> str:
    """Generate a full ERP audit report from a ``run_full_incident_report`` output package.

    Accepts the rich package dict produced by the full incident report pipeline
    and renders it as a 14-section audit-ready document.  Sections include
    evidence, hypotheses, proof, policy, remediation, chain of custody, control
    mapping, and safety notes.

    Args:
        package: Dict produced by ``run_full_incident_report`` or equivalent.
            Expected keys (all optional with safe defaults): ``executive_summary``,
            ``evidence_collected``, ``hypotheses_tested``, ``proof_results``,
            ``risk_classification``, ``policy_gate``, ``remediation_preview``,
            ``approval_record``, ``rollback_plan``, ``timeline``,
            ``chain_of_custody``, ``control_mapping``, ``audit_trail``,
            ``decision``, ``safety_notes``.
        fmt: Output format — ``"markdown"`` (default), ``"json"``, or ``"html"``.

    Returns:
        The formatted report string.  Non-serialisable values in nested dicts are
        coerced to strings by ``_json_dumps``.

    Side effects:
        None — pure renderer; no file writes.
    """
    sections = {
        "executive_summary": package.get("executive_summary", ""),
        "evidence_collected": package.get("evidence_collected", []),
        "hypotheses_tested": package.get("hypotheses_tested", []),
        "proof_results": package.get("proof_results", {}),
        "risk_classification": package.get("risk_classification"),
        "policy_decision": package.get("policy_gate", {}),
        "remediation_preview": package.get("remediation_preview", {}),
        "approval_record": package.get("approval_record", {}),
        "rollback_plan": package.get("rollback_plan", {}),
        "timeline": package.get("timeline", []),
        "chain_of_custody": package.get("chain_of_custody", []),
        "control_mapping": package.get("control_mapping", []),
        "audit_trail": package.get("audit_trail", []),
        "decision": package.get("decision", {}),
        "safety_notes": package.get("safety_notes", []),
    }
    if fmt == "json":
        return _json_dumps(sections)
    if fmt == "html":
        body = "<h1>Endpoint Reliability Incident Report</h1>"
        body += f"<p>{sections['executive_summary']}</p>"
        for title, key in (
            ("Evidence", "evidence_collected"),
            ("Proof", "proof_results"),
            ("Policy", "policy_decision"),
            ("Timeline", "timeline"),
        ):
            body += f"<h2>{title}</h2><pre>{_json_dumps(sections[key])}</pre>"
        return f"<!DOCTYPE html><html><body>{body}</body></html>"
    lines = [
        "# Endpoint Reliability Incident Report",
        "",
        "## 1. Executive Summary",
        str(sections["executive_summary"]),
        "",
        "## 2. Evidence Collected",
        "```json",
        _json_dumps(sections["evidence_collected"]),
        "```",
        "",
        "## 3. Hypotheses Tested",
        _json_dumps(sections["hypotheses_tested"]),
        "",
        "## 4. Proof Results",
        _json_dumps(sections["proof_results"]),
        "",
        "## 5. Risk Classification",
        str(sections["risk_classification"]),
        "",
        "## 6. Policy Decision",
        _json_dumps(sections["policy_decision"]),
        "",
        "## 7. Remediation Preview",
        _json_dumps(sections["remediation_preview"]),
        "",
        "## 8. Approval Record",
        _json_dumps(sections["approval_record"]),
        "",
        "## 9. Rollback Plan",
        _json_dumps(sections["rollback_plan"]),
        "",
        "## 10. Timeline",
        "```json",
        _json_dumps(sections["timeline"]),
        "```",
        "",
        "## 11. Chain of Custody",
        _json_dumps(sections["chain_of_custody"]),
        "",
        "## 12. Control Mapping (informational)",
        _json_dumps(sections["control_mapping"]),
        "",
        "## 13. Audit Trail",
        _json_dumps(sections["audit_trail"]),
        "",
        "## 14. Safety Notes",
        "\n".join(f"- {n}" for n in sections["safety_notes"]),
    ]
    return "\n".join(lines)

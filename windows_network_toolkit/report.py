"""Structured incident report from live proxy state and the audit trail.

Module responsibility:
    Assembles the canonical operator-facing proxy report by combining:
    classification, proof, risk scoring, audit event counts, policy-gate
    defaults, symptom analysis, and optional principle-compliance sections.
    All remediation references are preview-only by default; no Windows state
    is mutated here.

System placement:
    Called by the ``report`` CLI command and by integration tests that verify
    the full report shape.  Depends on ``classify_from_live``, ``run_diagnose_proof``,
    ``score_risk``, ``read_audit_logs``, and ``validate_principles``.

Key invariants:
    ``dry_run`` is always ``True`` in the default policy decision embedded in
    the report.  ``limitations[]`` in the returned dict must include entries
    from both the classification result and the proof result.

Side effects:
    When ``inject`` is ``None``: reads HKCU WinINET/WinHTTP registry keys,
    probes open TCP ports, and reads JSONL audit log files from disk.

Failure modes:
    Registry or audit-log I/O errors propagate from the underlying modules.
    Providing a malformed ``inject`` dict with ``include_principles=True``
    may raise ``KeyError`` during principle validation.

Audit Notes:
    ``_default_policy_decision`` embeds a hard-coded preview posture.  Callers
    that generate reports with ``include_principles=True`` must treat the
    compliance sections as informational management information, not formal
    audit opinions.
"""

from __future__ import annotations

from typing import Any

from src.platform_core.principles.report import build_principle_report_sections
from src.platform_core.principles.rules import format_confidence_display
from src.platform_core.principles.validator import build_incident_context, validate_principles
from windows_network_toolkit.audit_store import read_audit_logs
from windows_network_toolkit.platform.risk_scoring import score_risk
from windows_network_toolkit.proof import run_diagnose_proof
from windows_network_toolkit.proxy_classification import classify_from_live
from windows_network_toolkit.proxy_owner import detect_proxy_owner
from windows_network_toolkit.proxy_state import collect_proxy_state_model
from windows_network_toolkit.safety import DEFAULT_SAFETY_NOTES


def _default_policy_decision() -> dict[str, Any]:
    """Return the hard-coded preview-only policy decision embedded in all reports.

    Returns:
        A dict encoding a ``DISABLE_WININET_PROXY`` action in ``PREVIEW_ONLY``
        outcome mode.  ``allowed`` is always ``False``; ``dry_run`` is always
        ``True``.  Safety checks enumerate the blocked destructive categories
        (process kill, firewall reset, adapter disable, WinHTTP modification).
    """
    return {
        "action": "DISABLE_WININET_PROXY",
        "outcome": "PREVIEW_ONLY",
        "allowed": False,
        "requires_confirmation": True,
        "confirmation_token": "DISABLE_WININET_PROXY",
        "dry_run": True,
        "rollback_plan_present": True,
        "monitoring_recommended": True,
        "audit_logging": True,
        "safety_checks": [
            "no_process_kill",
            "no_firewall_reset",
            "no_adapter_disable",
            "no_winhttp_modification_unless_explicit",
        ],
    }


def build_proxy_report(
    *,
    url: str | None = None,
    inject: dict[str, Any] | None = None,
    include_principles: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    """Assemble the structured proxy incident report for the current endpoint state.

    Collects live Windows proxy evidence (or uses ``inject`` for deterministic
    tests), classifies the proxy state, runs the proof engine, scores risk,
    counts audit events, and optionally enriches the result with principle-
    compliance sections.

    Args:
        url: Optional URL to include in the proof-engine network-probe step.
        inject: Optional pre-built report dict.  When supplied without
            ``include_principles``, the dict is returned as-is.  When supplied
            with ``include_principles=True``, the dict is used as the base for
            principle validation.
        include_principles: When ``True``, validates the report against platform
            principles (``validate_principles``) and appends ``principle_compliance``,
            ``blocked_overclaims``, ``evidence_chain``, and
            ``safe_remediation_controls`` sections.
        **kwargs: Forwarded to ``collect_proxy_state_model``, ``detect_proxy_owner``,
            ``classify_from_live``, and ``run_diagnose_proof``.

    Returns:
        A dict containing:

        - ``executive_summary`` (str): One-line classification + confidence + proof status.
        - ``symptoms`` (list[str]): Observable failure indicators.
        - ``observations`` (dict): Raw proxy state and process owner evidence.
        - ``classification`` (dict): Classification label, confidence, evidence, limitations.
        - ``proof_status`` (dict): Hypothesis, proof attempts, conclusion, confidence.
        - ``risk_assessment`` (dict): Scored risk tier and contributing factors.
        - ``policy_decision`` (dict): Preview-only policy gate (dry_run always True).
        - ``limitations`` (list[str]): Combined classification + proof + safety caveats.
        - ``audit_event_count`` (int): Number of JSONL audit records found on disk.
        - *(principle sections when ``include_principles=True``)*

    Side effects:
        Live path: reads HKCU WinINET/WinHTTP registry keys, probes open TCP
        ports, reads JSONL audit log files from disk.  Inject path: none.

    Audit Notes:
        The embedded ``policy_decision`` is a default preview posture and does
        not authorise live remediation.  Reports containing
        ``include_principles=True`` sections are management information;
        they do not constitute formal audit opinions.
    """
    if inject and not include_principles:
        return inject

    if inject and include_principles:
        base = dict(inject)
    else:
        base = None

    if base is None:
        state = collect_proxy_state_model(**kwargs)
        owner = detect_proxy_owner(**kwargs)
        classification = classify_from_live(**kwargs)
        proof = run_diagnose_proof(url, **kwargs)
        risk = score_risk(classification, proof)
        audit_rows = read_audit_logs()

        symptoms = []
        if state.wininet_proxy_enabled and not owner.get("listener_found") and state.localhost_port:
            symptoms.append(
                "Browser may fail with ERR_PROXY_CONNECTION_FAILED while WinHTTP is direct."
            )
        if "WININET_WINHTTP_MISMATCH" in classification.secondary_signals:
            symptoms.append("WinINET and WinHTTP proxy configuration differ.")

        confidence_display = format_confidence_display(classification.confidence)
        base = {
            "executive_summary": (
                f"Proxy classification: {classification.primary_classification} "
                f"({confidence_display}). "
                f"Proof conclusion: {proof.conclusion_status}."
            ),
            "symptoms": symptoms
            or ["See observations — symptoms depend on application proxy usage."],
            "observations": {
                "proxy_state": state.to_dict(),
                "process_owner": owner,
            },
            "classification": classification.to_dict(),
            "evidence": classification.evidence,
            "proof_status": proof.to_dict(),
            "confidence_display": confidence_display,
            "remediation_status": {
                "recommended": classification.recommended_next_actions,
                "safe_default": "preview-only proxy-disable with typed confirmation",
            },
            "policy_decision": _default_policy_decision(),
            "dry_run": True,
            "rollback_plan_present": True,
            "monitoring_recommended": True,
            "audit_logging": True,
            "risk_assessment": risk,
            "limitations": classification.limitations
            + proof.limitations
            + DEFAULT_SAFETY_NOTES[:2],
            "recommended_next_actions": classification.recommended_next_actions,
            "audit_event_count": len(audit_rows),
        }

    if include_principles:
        validation_payload = {
            **base,
            "proof": base.get("proof_status") or base.get("proof"),
            "proxy_owner": (base.get("observations") or {}).get("process_owner"),
            "classification": base.get("classification"),
            "policy_decision": base.get("policy_decision") or _default_policy_decision(),
            "dry_run": base.get("dry_run", True),
            "rollback_plan_present": base.get("rollback_plan_present", True),
            "monitoring_recommended": base.get("monitoring_recommended", True),
            "audit_logging": base.get("audit_logging", True),
            "remediation_requested": base.get("remediation_requested", False),
        }
        compliance = validate_principles(validation_payload)
        ctx = build_incident_context(validation_payload)
        obs_dicts = [o.model_dump() for o in ctx["observations"]]
        sections = build_principle_report_sections(
            compliance=compliance,
            observations=obs_dicts,
            proof=validation_payload.get("proof") or base.get("proof_status"),
            classification=base.get("classification"),
            policy=validation_payload.get("policy_decision"),
            limitations=base.get("limitations"),
        )
        base.update(sections)
        base["confidence_display"] = compliance.confidence_display

    return base

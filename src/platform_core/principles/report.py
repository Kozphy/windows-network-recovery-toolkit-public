"""Report sections for principle compliance."""

from __future__ import annotations

from typing import Any

from src.platform_core.principles.models import (
    PrincipleComplianceResult,
)
from src.platform_core.principles.rules import format_confidence_display, load_principles_config


def build_evidence_chain(
    *,
    observations: list[dict[str, Any]] | None = None,
    proof: dict[str, Any] | None = None,
    classification: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Build evidence chain.

    Args:
        observations: observations supplied by the caller.
        proof: proof supplied by the caller.
        classification: classification supplied by the caller.

    Returns:
        The computed `list[dict[str, str]]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    chain: list[dict[str, str]] = []
    if observations:
        for obs in observations:
            chain.append(
                {
                    "tier": "OBSERVATION",
                    "signal": str(obs.get("signal", "")),
                    "value": str(obs.get("value", "")),
                    "note": "Observation — not proof.",
                }
            )
    if proof:
        for attempt in proof.get("proof_attempts") or []:
            chain.append(
                {
                    "tier": "PROOF_ATTEMPT",
                    "signal": str(attempt.get("name", "")),
                    "value": str(attempt.get("status", "")),
                    "note": str(attempt.get("meaning", "")),
                }
            )
        conclusion = proof.get("conclusion") or {}
        chain.append(
            {
                "tier": "PROOF_CONCLUSION",
                "signal": "conclusion",
                "value": str(conclusion.get("status") or proof.get("conclusion_status") or ""),
                "note": "Structured proof — still not certainty.",
            }
        )
    if classification:
        chain.append(
            {
                "tier": "CLASSIFICATION",
                "signal": str(classification.get("primary_classification", "")),
                "value": format_confidence_display(float(classification.get("confidence") or 0.0)),
                "note": "Heuristic classification.",
            }
        )
    return chain


def build_blocked_overclaims(compliance: PrincipleComplianceResult) -> list[str]:
    """Build blocked overclaims.

    Args:
        compliance: compliance supplied by the caller.

    Returns:
        The computed `list[str]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    cfg = load_principles_config()
    defaults = [
        "Does not prove malware without writer telemetry.",
        "Does not prove MITM without TLS/path proof.",
        "Listener correlation is not registry-writer causation.",
        "Confidence scores are ordinal — not probabilities.",
    ]
    blocked = list(dict.fromkeys(compliance.blocked_overclaims + defaults))
    for term in cfg.get("blocked_overclaim_terms", []):
        blocked.append(f"Blocked narrative: '{term}' without proof tier.")
    return blocked


def build_safe_remediation_controls(policy: dict[str, Any] | None = None) -> list[str]:
    """Build safe remediation controls.

    Args:
        policy: policy supplied by the caller.

    Returns:
        The computed `list[str]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    controls = [
        "Dry-run is default for all state-changing commands.",
        "Typed confirmation required for HKCU WinINET registry mutations.",
        "Rollback snapshot captured before apply.",
        "Post-change monitoring via proxy-watch recommended.",
        "Append-only audit JSONL for every preview and apply.",
        "Process kill, firewall reset, adapter disable, WinHTTP modify — blocked.",
    ]
    if policy:
        if policy.get("requires_confirmation"):
            controls.append(f"Confirmation token: {policy.get('confirmation_token', 'DISABLE_WININET_PROXY')}")
        if policy.get("safety_checks"):
            controls.extend(f"Safety check: {c}" for c in policy["safety_checks"])
    return controls


def build_principle_report_sections(
    *,
    compliance: PrincipleComplianceResult,
    observations: list[dict[str, Any]] | None = None,
    proof: dict[str, Any] | None = None,
    classification: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Build principle report sections.

    Args:
        compliance: compliance supplied by the caller.
        observations: observations supplied by the caller.
        proof: proof supplied by the caller.
        classification: classification supplied by the caller.
        policy: policy supplied by the caller.
        limitations: limitations supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    principle_compliance = {
        "compliant": compliance.compliant,
        "summary": compliance.summary,
        "confidence_display": compliance.confidence_display,
        "checks": [c.model_dump() for c in compliance.checks],
    }
    return {
        "evidence_chain": build_evidence_chain(
            observations=observations,
            proof=proof,
            classification=classification,
        ),
        "blocked_overclaims": build_blocked_overclaims(compliance),
        "principle_compliance": principle_compliance,
        "limitations": list(limitations or []) + [
            "Principle compliance does not guarantee endpoint safety.",
            "Heuristic confidence is ordinal — not probability.",
        ],
        "safe_remediation_controls": build_safe_remediation_controls(policy),
    }

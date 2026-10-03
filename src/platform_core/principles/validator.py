"""Principle validator — enforce epistemic contracts on incident payloads."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.platform_core.principles.models import (
    Attribution,
    Observation,
    PolicyDecision,
    PrincipleComplianceResult,
    ProofEnvelope,
    RiskDecision,
)
from src.platform_core.principles.rules import (
    check_classification_not_accusation,
    check_confidence_not_certainty,
    check_correlation_not_causation,
    check_observation_not_proof,
    check_policy_not_safety,
    check_recommendation_not_execution,
    format_confidence_display,
    load_principles_config,
)


def explain_principles() -> dict[str, Any]:
    """Return explain principles.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    cfg = load_principles_config()
    principles = cfg.get("principles", {})
    return {
        "schema_version": cfg.get("schema_version", "1.0"),
        "principles": [
            {
                "id": p["id"],
                "title": p["title"],
                "summary": p["summary"],
                "rule": p["rule"],
            }
            for p in principles.values()
        ],
        "required_policy_controls": cfg.get("required_policy_controls", []),
        "disclaimer": "Principle compliance improves decision quality; it does not guarantee endpoint safety.",
    }


def _observations_from_payload(data: dict[str, Any]) -> list[Observation]:
    observations: list[Observation] = []
    state = data.get("proxy_state") or data.get("observations", {}).get("proxy_state") or {}
    if state:
        if state.get("wininet_proxy_enabled") is not None:
            observations.append(
                Observation(
                    signal="wininet_proxy_enabled",
                    value=state.get("wininet_proxy_enabled"),
                    source="wininet_registry",
                )
            )
        if state.get("wininet_proxy_server"):
            observations.append(
                Observation(
                    signal="wininet_proxy_server",
                    value=str(state.get("wininet_proxy_server")),
                    source="wininet_registry",
                )
            )
        if state.get("localhost_port") is not None:
            observations.append(
                Observation(
                    signal="localhost_port",
                    value=state.get("localhost_port"),
                    source="netstat",
                )
            )
    owner = data.get("proxy_owner") or data.get("observations", {}).get("process_owner") or {}
    if owner:
        observations.append(
            Observation(
                signal="listener_found",
                value=bool(owner.get("listener_found")),
                source="netstat",
            )
        )
    return observations


def _proof_from_payload(data: dict[str, Any]) -> ProofEnvelope | None:
    raw = data.get("proof") or data.get("proof_status") or {}
    if not raw:
        return None
    conclusion = raw.get("conclusion") or {}
    attempts = raw.get("proof_attempts") or []
    status = str(conclusion.get("status") or raw.get("conclusion_status") or "")
    tier: str = "OBSERVED_ONLY"
    if status.lower() in {"supported", "confirmed", "proven"}:
        tier = "PROVEN"
    elif attempts:
        tier = "CORRELATED"
    return ProofEnvelope(
        hypothesis=str(raw.get("hypothesis") or ""),
        proof_attempts=list(attempts),
        conclusion_status=status,
        confidence=float(conclusion.get("confidence") or raw.get("confidence") or 0.0),
        limitations=list(raw.get("limitations") or []),
        proof_tier=tier,  # type: ignore[arg-type]
    )


def _attribution_from_payload(data: dict[str, Any]) -> Attribution | None:
    writer = data.get("writer_attribution") or {}
    owner = data.get("proxy_owner") or data.get("observations", {}).get("process_owner") or {}
    classification = data.get("classification") or {}
    if not writer and not owner and not classification:
        return None
    proc = owner.get("process") or {}
    return Attribution(
        listener_found=bool(owner.get("listener_found")),
        process_name=proc.get("name") or owner.get("process_name"),
        pid=proc.get("pid") or owner.get("pid"),
        registry_writer_confirmed=bool(writer.get("registry_writer_confirmed")),
        telemetry_sources=list(writer.get("telemetry_sources") or []),
        classification=str(
            writer.get("classification") or classification.get("primary_classification") or ""
        ),
        confidence_score=float(
            writer.get("confidence_score") or classification.get("confidence") or 0.0
        ),
    )


def _risk_from_payload(data: dict[str, Any]) -> RiskDecision | None:
    raw = data.get("classification") or {}
    if not raw:
        return None
    exec_summary = str(data.get("executive_summary") or "")
    return RiskDecision(
        primary_classification=str(raw.get("primary_classification") or ""),
        secondary_signals=list(raw.get("secondary_signals") or []),
        confidence=float(raw.get("confidence") or 0.0),
        severity=str(raw.get("severity") or "medium"),
        limitations=list(raw.get("limitations") or []),
        narrative=exec_summary,
    )


def _policy_from_payload(data: dict[str, Any]) -> PolicyDecision | None:
    raw = data.get("policy_decision") or data.get("remediation_status") or {}
    remediation = data.get("remediation") or {}
    if not raw and not remediation:
        return None
    policy_raw = raw if isinstance(raw, dict) and raw.get("action") else remediation
    if isinstance(policy_raw, dict) and not policy_raw.get("action"):
        policy_raw = data.get("policy_decision") or {}
    return PolicyDecision(
        action=str(policy_raw.get("action") or "DISABLE_WININET_PROXY"),
        outcome=str(
            policy_raw.get("outcome") or ("ALLOW" if policy_raw.get("allowed") else "PREVIEW_ONLY")
        ),
        allowed=bool(policy_raw.get("allowed")),
        requires_confirmation=bool(policy_raw.get("requires_confirmation", True)),
        confirmation_token=str(policy_raw.get("confirmation_token") or "DISABLE_WININET_PROXY"),
        dry_run=bool(policy_raw.get("dry_run", data.get("dry_run", True))),
        rollback_plan_present=bool(
            data.get("rollback_plan_present")
            or remediation.get("rollback_plan")
            or policy_raw.get("rollback_plan_present")
        ),
        monitoring_recommended=bool(
            data.get("monitoring_recommended", policy_raw.get("monitoring_recommended", True))
        ),
        audit_logging=bool(data.get("audit_logging", policy_raw.get("audit_logging", True))),
        safety_checks=list(policy_raw.get("safety_checks") or []),
    )


def build_incident_context(data: dict[str, Any]) -> dict[str, Any]:
    """Build incident context.

    Args:
        data: data supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return {
        "observations": _observations_from_payload(data),
        "proof": _proof_from_payload(data),
        "attribution": _attribution_from_payload(data),
        "risk": _risk_from_payload(data),
        "policy": _policy_from_payload(data),
        "narrative_text": str(data.get("executive_summary") or ""),
        "remediation_requested": bool(
            data.get("remediation_requested")
            or data.get("remediation_status")
            or data.get("policy_decision")
        ),
    }


def validate_principles(
    data: dict[str, Any],
    *,
    remediation_requested: bool | None = None,
) -> PrincipleComplianceResult:
    """Validate principles.

    Args:
        data: data supplied by the caller.
        remediation_requested: remediation requested supplied by the caller.

    Returns:
        The computed `PrincipleComplianceResult` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    ctx = build_incident_context(data)
    observations: list[Observation] = ctx["observations"]
    proof: ProofEnvelope | None = ctx["proof"]
    attribution: Attribution | None = ctx["attribution"]
    risk: RiskDecision | None = ctx["risk"]
    policy: PolicyDecision | None = ctx["policy"]
    narrative: str = ctx["narrative_text"]
    rem = (
        remediation_requested
        if remediation_requested is not None
        else bool(ctx["remediation_requested"])
    )

    checks = [
        check_observation_not_proof(
            observations=observations,
            proof=proof,
            remediation_requested=rem,
            policy=policy,
        ),
        check_correlation_not_causation(
            attribution=attribution,
            risk=risk,
            proof=proof,
            narrative_text=narrative,
        ),
        check_confidence_not_certainty(risk=risk, proof=proof, narrative_text=narrative),
        check_policy_not_safety(policy=policy),
        check_classification_not_accusation(risk=risk, narrative_text=narrative),
        check_recommendation_not_execution(
            policy=policy,
            remediation_requested=rem,
            narrative_text=narrative,
        ),
    ]

    blocked: list[str] = []
    for check in checks:
        blocked.extend(check.violations)

    score = 0.0
    if risk:
        score = risk.confidence
    elif proof:
        score = proof.confidence

    compliant = all(c.passed for c in checks)
    return PrincipleComplianceResult(
        compliant=compliant,
        checks=checks,
        blocked_overclaims=blocked,
        confidence_display=format_confidence_display(score)
        if score
        else "ordinal n/a (heuristic score, not probability)",
        summary="All epistemic principles satisfied."
        if compliant
        else "One or more principle violations detected.",
    )


def validate_fixture_path(path: str | Path) -> PrincipleComplianceResult:
    """Validate fixture path.

    Args:
        path: path supplied by the caller.

    Returns:
        The computed `PrincipleComplianceResult` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    import json

    fixture_path = Path(path)
    if not fixture_path.is_file():
        repo = Path(__file__).resolve().parents[3]
        for candidate in (
            repo / "case_studies" / "cs1_wininet_proxy_drift" / "fixture.json",
            repo / "tests" / "fixtures" / "enert" / fixture_path.name,
            repo / "case_studies" / "cs1_wininet_proxy_drift" / fixture_path.name,
        ):
            if candidate.is_file():
                fixture_path = candidate
                break
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    return validate_principles(
        data, remediation_requested=bool(data.get("remediation_requested", False))
    )

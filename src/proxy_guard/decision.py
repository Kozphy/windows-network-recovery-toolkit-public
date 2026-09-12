"""Final Proxy Guard decision synthesis with regression-aware policy outcomes.

Module responsibility:
    Translate policy branch + attribution confidence + connectivity validation into a single
    structured decision payload suitable for stdout and append-only audit JSONL.

System placement:
    Called from :mod:`src.proxy_guard.guard` after registry diff, attribution, policy, and
    optional rollback planning have already completed.

Key invariants:
    - Avoids writer-proof claims unless attribution mode is verified telemetry.
    - Preserves policy reason while appending regression qualifiers when needed.
    - Returns stable keys used by tests and pipeline consumers.
"""

from __future__ import annotations

from typing import Any

from .connectivity import ConnectivityValidation
from .models import AttributionResult, ProxyGuardPolicyDecision


def finalize_decision(
    *,
    policy_decision: ProxyGuardPolicyDecision,
    connectivity_validation: ConnectivityValidation,
    attribution: AttributionResult,
    parsed_is_localhost: bool,
) -> dict[str, Any]:
    """Build final decision envelope consumed by pipeline emitters.

    Args:
        policy_decision: Base policy verdict from transition evaluation.
        connectivity_validation: Pre/post connectivity regression analysis.
        attribution: Attribution result including confidence tier and evidence limits.
        parsed_is_localhost: Whether current proxy points to localhost/loopback.

    Returns:
        dict[str, Any]: Normalized decision payload with keys:
            ``decision``, ``reason``, ``matched_policy``, ``risk_level``,
            ``recommended_action``, ``connectivity_validation``, ``attribution``.

    Decision intent:
        Prevent false "safe allow" outcomes by promoting medium-risk actions when HTTPS/browser
        path regresses despite permissive localhost listener signals.

    Audit Notes:
        Attribution notes explicitly include heuristic limitations so incident reviews do not
        over-interpret listener correlation as registry-writer proof.
    """
    decision = "insufficient_evidence"
    risk = "low"
    action = "none"
    reason = policy_decision.reason

    if policy_decision.decision == "blocked":
        decision = "blocked_high_risk"
        risk = "high"
        action = "rollback_recommended" if policy_decision.rollback_allowed else "prompt_user"
    elif connectivity_validation.regression_detected:
        decision = "allowed_but_connectivity_regressed"
        risk = "medium"
        action = "restore_previous_proxy_or_prompt_user"
        reason = f"{policy_decision.reason}|{connectivity_validation.regression_type}"
    elif policy_decision.decision == "allowed":
        decision = "allowed_no_regression"
        risk = "low"
        action = "none"
    elif policy_decision.decision == "observe":
        decision = "insufficient_evidence"
        risk = "low"
        action = "prompt_user"

    notes = list(attribution.limitations)
    if parsed_is_localhost:
        notes.append(
            "Listener attribution identifies process listening on localhost proxy port; it does not prove registry writer."
        )
    if attribution.mode != "verified_eventlog":
        notes.append("No direct Sysmon/EventLog registry-write proof; candidate actor remains heuristic.")

    confidence = "high" if attribution.mode == "verified_eventlog" else "medium" if attribution.process else "low"
    return {
        "decision": decision,
        "reason": reason,
        "matched_policy": policy_decision.matched_rule,
        "risk_level": risk,
        "recommended_action": action,
        "connectivity_validation": connectivity_validation.to_jsonable(),
        "attribution": {
            "confidence": confidence,
            "method": attribution.mode,
            "candidate_actor": None if attribution.process is None else attribution.process.to_jsonable(),
            "notes": notes,
        },
    }


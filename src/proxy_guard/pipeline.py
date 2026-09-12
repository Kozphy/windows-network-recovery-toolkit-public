"""Serialize Proxy Guard pipeline outcomes for stdout and append-only audit sinks.

Module responsibility:
    Map internal policy decisions, risk buckets, and rollback hints into stable JSON
    payloads consumed by :mod:`audit`, :mod:`human_report`, and legacy JSONL mirrors.

System placement:
    Called from :mod:`guard` after registry diff, attribution merge, and policy
    evaluation — never performs registry writes itself.

Key invariants:
    * ``public_decision_label`` preserves operator-facing vocabulary (``observe`` →
      ``observe_only``).
    * Risk inference is deterministic from snapshots and policy rows only.

Output guarantees:
    JSON-serializable dicts with bounded string fields suitable for NDJSON append.

Side effects:
    None — pure formatting helpers.

Audit Notes:
    Downstream auditors should correlate ``policy_payload_for_audit`` rows with
    ``logs/proxy_guard_pipeline_audit.jsonl`` and stderr banners from
    :func:`human_report.format_proxy_guard_change`.
"""

from __future__ import annotations

from typing import Any, Literal

from .models import ProxyGuardPolicyDecision, ProxySnapshot
from .parser import ParsedProxy

RiskLevel = Literal["low", "medium", "high"]
RecAction = Literal["none", "rollback", "prompt_user"]
RollbackVerify = Literal["passed", "failed", "not_run"]


def public_decision_label(decision: str) -> str:
    """Map internal ``observe`` branch to operator-facing ``observe_only``."""

    return "observe_only" if decision == "observe" else decision


def infer_risk_level(
    gd: ProxyGuardPolicyDecision,
    *,
    curr_snap: ProxySnapshot,
    parsed_after: ParsedProxy,
) -> RiskLevel:
    """Heuristic risk bucket for dashboards (deterministic, no external calls)."""

    if gd.decision == "allowed":
        return "low"
    if gd.decision == "observe":
        return "low"
    if parsed_after.is_localhost_proxy:
        return "high"
    if (curr_snap.proxy_enable or 0) == 1 and (curr_snap.proxy_server or "").strip():
        return "high"
    return "medium"


def infer_recommended_action(gd: ProxyGuardPolicyDecision) -> RecAction:
    """Translate guarded policy outcome into remediation hints."""

    if gd.decision == "blocked" and gd.rollback_allowed:
        return "rollback"
    if gd.decision == "blocked" and not gd.rollback_allowed:
        return "prompt_user"
    if gd.decision == "observe" and "unknown_attribution" in gd.reason:
        return "prompt_user"
    return "none"


def policy_payload_for_audit(
    gd: ProxyGuardPolicyDecision,
    *,
    curr_snap: ProxySnapshot,
    parsed_after: ParsedProxy,
    final_decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build normalized ``policy`` subtree for pipeline JSONL.

    Args:
        gd: Base transition policy decision.
        curr_snap: Current proxy snapshot used for risk inference fallback.
        parsed_after: Parsed current ``ProxyServer`` metadata.
        final_decision:
            Optional regression-aware decision payload from ``decision.finalize_decision``.
            When provided, this function emits the final decision values directly.

    Returns:
        dict[str, Any]: Policy subtree with ``decision``, ``reason``, ``matched_policy``,
        ``risk_level``, and ``recommended_action``.
    """

    if final_decision is not None:
        return {
            "decision": final_decision.get("decision"),
            "reason": final_decision.get("reason"),
            "matched_policy": final_decision.get("matched_policy"),
            "risk_level": final_decision.get("risk_level"),
            "recommended_action": final_decision.get("recommended_action"),
        }
    return {
        "decision": public_decision_label(gd.decision),
        "reason": gd.reason,
        "matched_policy": gd.matched_rule,
        "risk_level": infer_risk_level(gd, curr_snap=curr_snap, parsed_after=parsed_after),
        "recommended_action": infer_recommended_action(gd),
    }


def rollback_payload_for_audit(
    *,
    action: str,
    restored_fields: list[str],
    verification: RollbackVerify,
    error: str | None,
) -> dict[str, Any]:
    """Unified ``rollback`` subtree matching pipeline contract."""

    return {
        "action": action,
        "restored_fields": restored_fields,
        "verification": verification,
        "error": error,
    }


def summarize_stdout_event(
    gd: ProxyGuardPolicyDecision,
    *,
    rollback_subtree: dict[str, Any],
    curr_snap: ProxySnapshot,
    parsed_after: ParsedProxy,
    final_decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create console JSON summary while preserving backward-compatible fields.

    Args:
        gd: Base policy decision.
        rollback_subtree: Rollback action payload.
        curr_snap: Current snapshot for risk fallback when ``final_decision`` is absent.
        parsed_after: Parsed current proxy metadata for fallback risk inference.
        final_decision:
            Optional full decision envelope (connectivity + attribution + evidence).

    Returns:
        dict[str, Any]: Human-facing stdout blob containing policy, rollback, and optional
        connectivity/attribution/evidence subtrees.

    Audit Notes:
        Keep this payload aligned with pipeline JSONL keys so incident responders can compare
        terminal output against append-only audit lines.
    """

    pol = policy_payload_for_audit(
        gd,
        curr_snap=curr_snap,
        parsed_after=parsed_after,
        final_decision=final_decision,
    )
    connectivity_blob = {}
    attribution_blob = {}
    evidence_blob = []
    if final_decision is not None:
        connectivity_blob = final_decision.get("connectivity_validation") or {}
        attribution_blob = final_decision.get("attribution") or {}
        evidence_blob = final_decision.get("evidence") or []
    return {
        "decision": pol["decision"],
        "reason": pol["reason"],
        "matched_policy": pol["matched_policy"],
        "risk_level": pol["risk_level"],
        "recommended_action": pol["recommended_action"],
        "rollback": {
            "action": rollback_subtree["action"],
            "restored_fields": rollback_subtree["restored_fields"],
            "verification": rollback_subtree["verification"],
            "error": rollback_subtree["error"],
        },
        "connectivity_validation": connectivity_blob,
        "attribution": attribution_blob,
        "evidence": evidence_blob,
        "legacy_detail": gd.reason,
    }


def disabling_transition_allowed(prior: ProxySnapshot, curr: ProxySnapshot) -> bool:
    """Return True when operator appears to disable WinINET proxy via toggle."""

    pe_b = int(prior.proxy_enable or 0)
    pe_a = int(curr.proxy_enable or 0)
    if pe_b == 1 and pe_a == 0:
        return True
    return False

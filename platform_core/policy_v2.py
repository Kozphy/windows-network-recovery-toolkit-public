"""Policy engine v2 vocabulary: tri-state outcomes, reason codes, blocked actions.

Additive contract for dashboards, audit JSONL, and replay viewers. Legacy snake_case
codes in :mod:`platform_core.policy.engine` remain for backward compatibility; reasoning
policy in :mod:`platform_core.reasoning_engine` emits these canonical codes.

Audit Notes:
    ``blocked_actions`` lists actions that must not execute under this decision even when
    outcome is PREVIEW (operator may still preview safe-tier actions explicitly).
"""

from __future__ import annotations

from typing import Any, Literal

PolicyTriState = Literal["ALLOW", "PREVIEW", "BLOCK"]

# Canonical reason codes (machine-diffable, uppercase).
DESTRUCTIVE_ACTION_BLOCKED = "DESTRUCTIVE_ACTION_BLOCKED"
UNKNOWN_ACTION = "UNKNOWN_ACTION"
DIAGNOSTIC_ONLY = "DIAGNOSTIC_ONLY"
CONFLICTING_SIGNALS = "CONFLICTING_SIGNALS"
CONFIRMED_SAFE_TIER_WITH_CONFIRMATION = "CONFIRMED_SAFE_TIER_WITH_CONFIRMATION"
REQUIRES_OPERATOR_CONFIRMATION = "REQUIRES_OPERATOR_CONFIRMATION"
PREVIEW_UNTIL_PROOF = "PREVIEW_UNTIL_PROOF"
HIGH_IMPACT_UNPROVEN = "HIGH_IMPACT_UNPROVEN"
CRITICAL_IMPACT_LOW_TRUST = "CRITICAL_IMPACT_LOW_TRUST"
HIGH_CONFIDENCE_UNPROVEN = "HIGH_CONFIDENCE_UNPROVEN"
REQUIRES_TYPED_CONFIRMATION = "REQUIRES_TYPED_CONFIRMATION"
SAFE_TIER_ACTION = "SAFE_TIER_ACTION"
HEURISTIC_ATTRIBUTION_NOT_WRITER_PROOF = "HEURISTIC_ATTRIBUTION_NOT_WRITER_PROOF"
LISTENER_CORRELATION_NOT_WRITER_PROOF = "LISTENER_CORRELATION_NOT_WRITER_PROOF"
PROOF_REJECTED_FOR_HYPOTHESIS = "PROOF_REJECTED_FOR_HYPOTHESIS"
LOW_CONFIDENCE_BLOCK = "LOW_CONFIDENCE_BLOCK"
TRUST_DEGRADED_CAP_TO_PREVIEW = "TRUST_DEGRADED_CAP_TO_PREVIEW"

ALWAYS_BLOCKED_ACTIONS: tuple[str, ...] = (
    "firewall_reset",
    "reset_firewall",
    "adapter_disable",
    "process_kill",
    "kill",
    "arbitrary_shell",
    "arbitrary_command",
    "delete_certificates",
    "netsh_reset",
)

SAFE_TIER_ACTIONS: frozenset[str] = frozenset(
    {
        "restore_proxy",
        "disable_proxy",
        "reset_wininet_proxy",
        "restore_known_good_proxy",
        "reset_dns",
        "reset_proxy",
        "inspect_proxy",
    },
)


def blocked_actions_for_request(
    *,
    outcome: PolicyTriState,
    requested_action: str | None,
) -> list[str]:
    """Return action keys that must not auto-execute under this policy envelope."""
    blocked = list(ALWAYS_BLOCKED_ACTIONS)
    action = (requested_action or "").strip().lower()
    if outcome == "BLOCK" and action and action not in blocked:
        blocked.append(action)
    return list(dict.fromkeys(blocked))


def policy_envelope(
    *,
    decision: PolicyTriState,
    reason_codes: list[str],
    requested_action: str | None = None,
    blocked_actions: list[str] | None = None,
) -> dict[str, Any]:
    """Build a JSON-serializable policy decision block for APIs and audit rows."""
    ba = (
        blocked_actions
        if blocked_actions is not None
        else blocked_actions_for_request(
            outcome=decision,
            requested_action=requested_action,
        )
    )
    return {
        "decision": decision,
        "reason_codes": list(dict.fromkeys(reason_codes)),
        "blocked_actions": ba,
    }

"""Safety constants and blocked-action registry.

Module responsibility:
    Centralize blocked destructive actions, typed confirmation tokens, and default
    safety notes referenced by policy gates and remediation preview/apply paths.

System placement:
    Imported by remediation modules (``proxy_remediation``, ``ipv6_path``), CLI
    handlers, and policy evaluation. Documents non-negotiable toolkit boundaries.

Key invariants:
    * ``BLOCKED_ACTIONS`` includes process kill, firewall reset, adapter disable, WinHTTP modify.
    * Dry-run is the default posture for state-changing commands (enforced in callers).
    * Confirmation tokens are case-sensitive exact-match phrases — partial phrases block apply.

Side effects:
    None — constants and pure helpers only.

Audit Notes:
    Receiving ``action_allowed: False`` means the token was absent/wrong or the action
    is blocked. Evidence: remediation JSON output + ``.audit/*.jsonl`` rows.
"""

from __future__ import annotations

import os

BLOCKED_ACTIONS = frozenset(
    {
        "KILL_PROXY_PROCESS",
        "FIREWALL_RESET",
        "ADAPTER_DISABLE",
        "WINHTTP_MODIFY",
    }
)

# Typed confirmation tokens required by gated apply paths (proxy disable, prefer-IPv4, …).
# The operator must pass the exact token string as the ``confirm`` parameter; a partial
# or modified phrase is treated as an unsigned apply attempt and results in a blocked audit row.
# Audit Notes:
#   Each entry maps action_id → typed phrase that must match literally (case-sensitive).
#   Receiving ``action_allowed: False`` in the output means the token was absent or wrong.
CONFIRMATION_TOKENS = {
    "DISABLE_WININET_PROXY": "DISABLE_WININET_PROXY",
    "PREFER_IPV4_OVER_IPV6": "PREFER_IPV4_OVER_IPV6",
    "RESTORE_IPV6_PREFERENCE": "RESTORE_IPV6_PREFERENCE",
    "FIX_ERR_NAME_NOT_RESOLVED": "FIX_ERR_NAME_NOT_RESOLVED",
    "CLEAR_EDGE_BLANK_SCREEN_CACHES": "CLEAR_EDGE_BLANK_SCREEN_CACHES",
    "BROWSER_SITE_REPAIR_APPLY": "BROWSER_SITE_REPAIR_APPLY",
    "DISABLE_EDGE_EXTENSIONS_VIA_POLICY": "DISABLE_EDGE_EXTENSIONS_VIA_POLICY",
    "RESTORE_EDGE_EXTENSIONS_POLICY": "RESTORE_EDGE_EXTENSIONS_POLICY",
}

# Standard limitation/caveat lines included in every state-changing command output.
# Referenced by remediation preview, policy evaluation, and report generation helpers
# to ensure the governance envelope always carries epistemic context.
DEFAULT_SAFETY_NOTES = [
    "Observation is not proof; correlation is not causation.",
    "Dry-run is default for all state-changing commands.",
    "No silent process kill, firewall reset, adapter disable, or WinHTTP modification.",
    "Policy permission is not a safety guarantee.",
]

POLICY_DISCLAIMER = (
    "This toolkit provides evidence-based endpoint diagnosis — not antivirus or EDR replacement."
)


def safety_checks_for(action: str) -> list[str]:
    """Return safety check labels applied before evaluating an action.

    Args:
        action: Requested action identifier (e.g. ``KILL_PROXY_PROCESS``).

    Returns:
        List of check tokens; includes ``blocked_action:<name>`` when action is blocked.
    """
    checks = [
        "no_process_kill",
        "no_firewall_reset",
        "no_adapter_disable",
        "no_winhttp_modification_unless_explicit",
    ]
    if action in BLOCKED_ACTIONS:
        checks.append(f"blocked_action:{action}")
    return checks


def is_demo_mode() -> bool:
    """Return True when DEMO_MODE env enables reviewer demo safety gates."""
    return os.environ.get("DEMO_MODE", "").lower() in ("1", "true", "yes")


def is_blocked_action(action: str) -> bool:
    """Return whether an action is in the blocked destructive registry.

    Args:
        action: Action identifier (case-insensitive).

    Returns:
        True when action is in ``BLOCKED_ACTIONS`` or ``DEMO_MODE`` is active.

    Side effects:
        None.
    """
    if is_demo_mode():
        return True
    return action.upper() in BLOCKED_ACTIONS

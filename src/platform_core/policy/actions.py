"""Destructive-action registry and normalisation helpers.

Module responsibility:
    Defines the canonical set of destructive action identifiers (sourced from the
    ``DestructiveAction`` enum in ``contracts``), aliases that map legacy or
    human-readable action names to canonical keys, and two helper functions for
    normalisation and destructive-action detection.

System placement:
    Consumed by the policy engine (``policy/engine.py``) and the safety layer
    (``windows_network_toolkit/safety.py``) before any action is evaluated for
    execution authority.  This module is read-only; it does not execute or schedule
    any action.

Key invariants:
    ``DESTRUCTIVE_ACTIONS`` is a ``frozenset`` derived from the ``DestructiveAction``
    enum at import time and must remain immutable.  ``ACTION_ALIASES`` must not be
    mutated at runtime.

Side effects:
    None.

Failure modes:
    If the ``DestructiveAction`` enum in ``contracts`` gains new members without a
    corresponding alias entry, ``is_destructive`` may produce a false negative for
    caller-supplied action strings that match the new member name only via alias.
"""

from __future__ import annotations

from src.platform_core.contracts import DestructiveAction

DESTRUCTIVE_ACTIONS: frozenset[str] = frozenset(a.value for a in DestructiveAction)

ACTION_ALIASES: dict[str, str] = {
    "disable_wininet_proxy": DestructiveAction.DISABLE_PROXY.value,
    "stop_proxy_listener": DestructiveAction.KILL_PROCESS.value,
    "stop_proxy_reverter": DestructiveAction.KILL_PROCESS.value,
    "registry_modification": DestructiveAction.REGISTRY_MODIFICATION.value,
    "reset_firewall": DestructiveAction.FIREWALL_RESET.value,
    "adapter_disable": DestructiveAction.ADAPTER_DISABLE.value,
}


def normalize_action(action: str) -> str:
    """Return the canonical action key for *action*, resolving legacy aliases.

    Args:
        action: Raw action string from CLI, YAML policy, or audit record.  May
            contain hyphens, mixed case, or leading/trailing whitespace.

    Returns:
        Lower-cased, underscore-normalised action key.  If *action* matches a
        known alias in ``ACTION_ALIASES``, the canonical ``DestructiveAction``
        value is returned instead.
    """
    key = action.strip().lower().replace("-", "_")
    return ACTION_ALIASES.get(key, key)


def is_destructive(action: str) -> bool:
    """Return ``True`` when *action* maps to a known destructive operation.

    Checks both the canonical ``DESTRUCTIVE_ACTIONS`` registry and a substring
    heuristic (``disable``, ``kill``, ``reset``, ``delete``) as a conservative
    catch-all for unregistered action names.

    Args:
        action: Raw or canonical action string.

    Returns:
        ``True`` if the normalised action is in ``DESTRUCTIVE_ACTIONS`` or
        contains a known-dangerous substring; ``False`` otherwise.

    Engineering Notes:
        The substring fallback is intentionally conservative: an action with
        ``"disable"`` in its name is flagged even if not explicitly registered.
        This guards against typo-based bypasses without requiring an exhaustive
        enum entry for every variant.
    """
    norm = normalize_action(action)
    return norm in DESTRUCTIVE_ACTIONS or any(
        d in norm for d in ("disable", "kill", "reset", "delete")
    )

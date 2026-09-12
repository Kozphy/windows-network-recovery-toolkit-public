"""Factories for append-only Proxy Guard JSONL records.

Schemas stay intentionally flat for ``json.loads(line)`` review in text editors.
"""

from __future__ import annotations

from typing import Any

from ..core.time_utils import utc_now_iso


def proxy_guard_event(
    *,
    event_type: str,
    registry_view: dict[str, Any],
    owners: dict[str, Any] | None = None,
    notes: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Build one JSONL-safe event row."""
    return {
        "type": "proxy_guard",
        "event_type": event_type,
        "timestamp": utc_now_iso(),
        "registry": registry_view,
        "owners": owners or {},
        "notes": list(notes),
    }


def proxy_guard_control_event(
    *,
    event_type: str,
    previous_registry_view: dict[str, Any],
    current_registry_view: dict[str, Any],
    attribution: dict[str, Any],
    policy_source: str,
    decision: str,
    decision_detail: str,
    action: str,
    matched_rule: str | None,
    primary_process_name: str | None = None,
    rollback_detail: dict[str, Any] | None = None,
    post_rollback_registry_view: dict[str, Any] | None = None,
    probe_notes: tuple[str, ...] | None = None,
    rollback_suppressed_reason: str | None = None,
) -> dict[str, Any]:
    """Build a control-plane audit row (policy + optional safe rollback).

    Schema notes:
        ``decision`` is typically ``allowed``, ``blocked``, or ``informational`` (baseline).
        ``action`` is ``none``, ``rollback``, or ``suppressed`` (rate limit / cooldown).
    """
    row: dict[str, Any] = {
        "type": "proxy_guard_control",
        "event_type": event_type,
        "timestamp": utc_now_iso(),
        "previous_registry_view": previous_registry_view,
        "current_registry_view": current_registry_view,
        "attribution": attribution,
        "policy": {"source_path": policy_source},
        "decision": decision,
        "decision_detail": decision_detail,
        "action": action,
        "matched_rule": matched_rule,
    }
    if primary_process_name is not None:
        row["primary_process_name"] = primary_process_name
    if rollback_detail is not None:
        row["rollback_detail"] = rollback_detail
    if post_rollback_registry_view is not None:
        row["post_rollback_registry_view"] = post_rollback_registry_view
    if probe_notes:
        row["probe_notes"] = list(probe_notes)
    if rollback_suppressed_reason is not None:
        row["rollback_suppressed_reason"] = rollback_suppressed_reason
    return row

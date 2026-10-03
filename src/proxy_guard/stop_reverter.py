"""Operator-confirmed termination of attributed proxy reverter parent processes.

Pipeline position:
    Invoked from ``proxy-stop-reverter`` and optional ``proxy-disable --stop-reverter-first``.

Key invariants:
    * Targets only the parent ``powershell.exe`` tree correlated to the listener row from
      :mod:`stop_listener` attribution — not generic ``kill_process``.
    * Live execution requires ``STOP_PROXY_REVERTER``, Administrator elevation, and a resolved
      parent PID on an eligible parent name.
"""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..core.time_utils import utc_now_iso
from .remediation import Decision, get_remediation_action
from .stop_listener import (
    LISTENER_ATTRIBUTION_LIMITATION,
    StopListenerTarget,
    build_taskkill_argv,
    execute_taskkill,
    is_windows_admin,
    resolve_stop_listener_target,
)

STOP_PROXY_REVERTER_PHRASE = "STOP_PROXY_REVERTER"
ACTION_ID = "stop_proxy_reverter"

REVERTER_ATTRIBUTION_LIMITATION = (
    "Parent process correlation is not registry-writer proof; stopping the parent may not "
    "prevent proxy re-enable if a scheduled task or service respawns the reverter."
)

_ELIGIBLE_PARENT_NAMES = frozenset({"powershell.exe", "pwsh.exe"})


@dataclass(frozen=True)
class StopReverterResult:
    """Outcome of a stop-reverter workflow including audit-friendly fields."""

    action_id: str
    decision: Decision
    dry_run: bool
    mutated: bool
    reason: str
    target: StopListenerTarget | None
    parent_pid: int | None
    before: dict[str, Any]
    after: dict[str, Any] | None
    planned_argv: tuple[str, ...]
    taskkill_result: dict[str, Any] | None
    notes: tuple[str, ...]

    def to_audit_row(self, *, event_kind: str) -> dict[str, Any]:
        """To audit row.

        Args:
            event_kind: The event kind value supplied by the caller.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        return {
            "audit_event_id": str(uuid.uuid4()),
            "type": "repair",
            "subtype": "proxy_stop_reverter",
            "event_kind": event_kind,
            "action_id": self.action_id,
            "decision": self.decision,
            "dry_run": self.dry_run,
            "mutated": self.mutated,
            "reason": self.reason,
            "timestamp": utc_now_iso(),
            "before": self.before,
            "after": self.after,
            "planned_action": {
                "argv": list(self.planned_argv),
                "human": [self._human_preview()],
            },
            "taskkill_result": self.taskkill_result or {},
            "listener_target": self.target.to_dict() if self.target else None,
            "parent_pid": self.parent_pid,
            "notes": list(self.notes),
            "confirmation_method": "typed_phrase",
            "limitation": REVERTER_ATTRIBUTION_LIMITATION,
        }

    def _human_preview(self) -> str:
        if self.parent_pid is None:
            return "No eligible parent powershell PID resolved; taskkill not planned."
        parent = (self.target.parent_name if self.target else None) or "powershell.exe"
        listener = self.target.pid if self.target else "?"
        return (
            f"taskkill /F /PID {self.parent_pid} /T  (parent {parent} of listener PID {listener})"
        )


def is_eligible_reverter_parent(parent_name: str | None) -> bool:
    """Return True when ``parent_name`` matches an allowlisted reverter parent executable."""

    if not parent_name:
        return False
    return parent_name.strip().lower() in _ELIGIBLE_PARENT_NAMES


def resolve_reverter_parent_pid(target: StopListenerTarget | None) -> int | None:
    """Return parent PID when the listener row names an eligible reverter parent."""

    if target is None or target.parent_pid is None:
        return None
    if not is_eligible_reverter_parent(target.parent_name):
        return None
    return int(target.parent_pid)


def evaluate_stop_reverter_policy(
    *,
    dry_run: bool,
    confirmation: str,
    target: StopListenerTarget | None,
    parent_pid: int | None,
    elevated: bool | None = None,
) -> tuple[Decision, str]:
    """Return policy decision for stop-reverter (PREVIEW, ALLOW, or BLOCK)."""

    action = get_remediation_action(ACTION_ID)
    if action is None or action.blocked_reason:
        return "BLOCK", action.blocked_reason if action else "unknown_action"

    if target is None:
        return "BLOCK", "no_listener_pid"

    if parent_pid is None:
        return "BLOCK", "no_eligible_parent_pid"

    if dry_run:
        return "PREVIEW", "dry_run_preview_only"

    phrase = confirmation.strip()
    if not phrase:
        return "BLOCK", "missing_confirmation"
    if phrase != STOP_PROXY_REVERTER_PHRASE:
        return "BLOCK", "confirmation_mismatch"

    is_elevated = is_windows_admin() if elevated is None else elevated
    if not is_elevated:
        return "BLOCK", "administrator_elevation_required"

    return "ALLOW", "confirmed_allowlisted_action"


def run_stop_reverter_workflow(
    *,
    dry_run: bool,
    confirmation: str = "",
    port: int | None = None,
    elevated: bool | None = None,
    run: Callable[..., Any] = subprocess.run,
) -> StopReverterResult:
    """Preview or execute scoped parent ``powershell`` tree termination."""

    target, notes = resolve_stop_listener_target(port=port, run=run)
    parent_pid = resolve_reverter_parent_pid(target)
    before = {
        "target": target.to_dict() if target else None,
        "parent_pid": parent_pid,
        "elevated": is_windows_admin() if elevated is None else elevated,
    }
    decision, reason = evaluate_stop_reverter_policy(
        dry_run=dry_run,
        confirmation=confirmation,
        target=target,
        parent_pid=parent_pid,
        elevated=elevated,
    )
    planned_argv = build_taskkill_argv(parent_pid) if parent_pid else tuple()
    taskkill_result: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    mutated = False

    if decision == "ALLOW" and parent_pid is not None:
        taskkill_result = execute_taskkill(parent_pid, run=run)
        mutated = bool(taskkill_result.get("success"))
        after = {
            "taskkill_result": taskkill_result,
            "parent_pid": parent_pid,
            "target": target.to_dict() if target else None,
        }
        if not mutated:
            decision = "BLOCK"
            reason = "taskkill_failed"

    all_notes = (REVERTER_ATTRIBUTION_LIMITATION, LISTENER_ATTRIBUTION_LIMITATION, *notes)
    return StopReverterResult(
        action_id=ACTION_ID,
        decision=decision,
        dry_run=dry_run,
        mutated=mutated,
        reason=reason,
        target=target,
        parent_pid=parent_pid,
        before=before,
        after=after,
        planned_argv=planned_argv,
        taskkill_result=taskkill_result,
        notes=all_notes,
    )

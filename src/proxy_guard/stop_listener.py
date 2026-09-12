"""Operator-confirmed termination of localhost proxy listener processes.

Pipeline position:
    Invoked from ``proxy-stop-listener`` and optional ``proxy-disable --stop-listener-first``.

Key invariants:
    * Default posture is preview-only (no ``taskkill``).
    * Live execution requires typed ``STOP_PROXY_LISTENER``, Administrator elevation, and a
      resolved listener PID from :mod:`owner` attribution (not registry-writer proof).
    * Distinct from blocked ``kill_process`` — scoped to attributed localhost proxy port only.
"""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..core.time_utils import utc_now_iso
from .owner import resolve_localhost_proxy_owners
from .parser import parse_proxy_server
from .registry import read_proxy_registry
from .remediation import Decision, get_remediation_action

STOP_PROXY_LISTENER_PHRASE = "STOP_PROXY_LISTENER"
ACTION_ID = "stop_proxy_listener"

LISTENER_ATTRIBUTION_LIMITATION = (
    "Listener correlation is not registry-writer proof; stopping the listener may not stop "
    "proxy re-enable if another process writes HKCU keys."
)


def is_windows_admin() -> bool:
    """Return True when the current token has Administrator elevation on Windows."""

    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError, ImportError):
        return False


@dataclass(frozen=True)
class StopListenerTarget:
    """Resolved listener row eligible for ``taskkill`` preview or execution."""

    port: int
    pid: int
    process_name: str | None
    parent_pid: int | None
    parent_name: str | None

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "port": self.port,
            "pid": self.pid,
            "process_name": self.process_name,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
        }


@dataclass(frozen=True)
class StopListenerResult:
    """Outcome of a stop-listener workflow including audit-friendly fields."""

    action_id: str
    decision: Decision
    dry_run: bool
    mutated: bool
    reason: str
    target: StopListenerTarget | None
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
            "subtype": "proxy_stop_listener",
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
            "notes": list(self.notes),
            "confirmation_method": "typed_phrase",
            "limitation": LISTENER_ATTRIBUTION_LIMITATION,
        }

    def _human_preview(self) -> str:
        if self.target is None:
            return "No listener PID resolved; taskkill not planned."
        name = self.target.process_name or "unknown"
        parent = self.target.parent_name or "unknown"
        return (
            f"taskkill /F /PID {self.target.pid} /T  "
            f"({name} on 127.0.0.1:{self.target.port}, parent {parent})"
        )


def resolve_stop_listener_target(
    *,
    port: int | None = None,
    run: Callable[..., Any] = subprocess.run,
) -> tuple[StopListenerTarget | None, tuple[str, ...]]:
    """Resolve the first attributed listener for ``port`` or parsed HKCU proxy port."""

    notes: list[str] = []
    resolved_port = port
    if resolved_port is None:
        reg = read_proxy_registry(run=run)
        parsed = parse_proxy_server(reg.proxy_server)
        resolved_port = parsed.localhost_port
        if resolved_port is None:
            notes.append("No localhost proxy port parsed from HKCU ProxyServer; pass --port explicitly.")

    if resolved_port is None:
        return None, tuple(notes)

    owners, owner_notes = resolve_localhost_proxy_owners(resolved_port, run=run)
    notes.extend(owner_notes)
    if not owners:
        notes.append("No listener owner rows resolved; cannot plan taskkill.")
        return None, tuple(notes)

    primary = owners[0]
    if primary.pid is None:
        notes.append("Owner row missing PID; cannot plan taskkill.")
        return None, tuple(notes)

    return (
        StopListenerTarget(
            port=resolved_port,
            pid=int(primary.pid),
            process_name=primary.process_name,
            parent_pid=primary.parent_pid,
            parent_name=primary.parent_name,
        ),
        tuple(notes),
    )


def build_taskkill_argv(pid: int) -> tuple[str, ...]:
    """Return Windows ``taskkill`` argv for process tree termination."""

    return ("taskkill", "/F", "/PID", str(pid), "/T")


def evaluate_stop_listener_policy(
    *,
    dry_run: bool,
    confirmation: str,
    target: StopListenerTarget | None,
    elevated: bool | None = None,
) -> tuple[Decision, str]:
    """Return policy decision for stop-listener (PREVIEW, ALLOW, or BLOCK)."""

    action = get_remediation_action(ACTION_ID)
    if action is None or action.blocked_reason:
        return "BLOCK", action.blocked_reason if action else "unknown_action"

    if target is None:
        return "BLOCK", "no_listener_pid"

    if dry_run:
        return "PREVIEW", "dry_run_preview_only"

    phrase = confirmation.strip()
    if not phrase:
        return "BLOCK", "missing_confirmation"
    if phrase != STOP_PROXY_LISTENER_PHRASE:
        return "BLOCK", "confirmation_mismatch"

    is_elevated = is_windows_admin() if elevated is None else elevated
    if not is_elevated:
        return "BLOCK", "administrator_elevation_required"

    return "ALLOW", "confirmed_allowlisted_action"


def execute_taskkill(
    pid: int,
    *,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Run ``taskkill`` and return structured subprocess metadata."""

    argv = build_taskkill_argv(pid)
    try:
        proc = run(
            list(argv),
            capture_output=True,
            text=True,
            shell=False,
            timeout=60,
        )
        return {
            "argv": list(argv),
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "")[:4000],
            "stderr": (proc.stderr or "")[:4000],
            "success": proc.returncode == 0,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "argv": list(argv),
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc)[:4000],
            "success": False,
        }


def run_stop_listener_workflow(
    *,
    dry_run: bool,
    confirmation: str = "",
    stop_parent_tree: bool = False,
    reverter_confirmation: str = "",
    port: int | None = None,
    elevated: bool | None = None,
    run: Callable[..., Any] = subprocess.run,
) -> StopListenerResult:
    """Preview or execute scoped listener termination with policy gates."""

    target, notes = resolve_stop_listener_target(port=port, run=run)
    parent_pid: int | None = None
    parent_planned_argv: tuple[str, ...] = tuple()
    parent_taskkill_result: dict[str, Any] | None = None

    if stop_parent_tree:
        from .stop_reverter import evaluate_stop_reverter_policy, resolve_reverter_parent_pid

        parent_pid = resolve_reverter_parent_pid(target)
        parent_planned_argv = build_taskkill_argv(parent_pid) if parent_pid else tuple()
        if not dry_run:
            rev_decision, rev_reason = evaluate_stop_reverter_policy(
                dry_run=False,
                confirmation=reverter_confirmation,
                target=target,
                parent_pid=parent_pid,
                elevated=elevated,
            )
            if rev_decision != "ALLOW":
                before = {
                    "target": target.to_dict() if target else None,
                    "elevated": is_windows_admin() if elevated is None else elevated,
                    "stop_parent_tree": True,
                    "parent_pid": parent_pid,
                    "parent_planned_argv": list(parent_planned_argv),
                }
                all_notes = (LISTENER_ATTRIBUTION_LIMITATION, *notes)
                return StopListenerResult(
                    action_id=ACTION_ID,
                    decision="BLOCK",
                    dry_run=dry_run,
                    mutated=False,
                    reason=rev_reason,
                    target=target,
                    before=before,
                    after=None,
                    planned_argv=parent_planned_argv or (build_taskkill_argv(target.pid) if target else tuple()),
                    taskkill_result=None,
                    notes=all_notes,
                )
            if parent_pid is not None:
                parent_taskkill_result = execute_taskkill(parent_pid, run=run)
                if not parent_taskkill_result.get("success"):
                    before = {
                        "target": target.to_dict() if target else None,
                        "elevated": is_windows_admin() if elevated is None else elevated,
                        "stop_parent_tree": True,
                        "parent_pid": parent_pid,
                        "parent_planned_argv": list(parent_planned_argv),
                    }
                    all_notes = (LISTENER_ATTRIBUTION_LIMITATION, *notes)
                    return StopListenerResult(
                        action_id=ACTION_ID,
                        decision="BLOCK",
                        dry_run=dry_run,
                        mutated=False,
                        reason="parent_taskkill_failed",
                        target=target,
                        before=before,
                        after={"parent_taskkill_result": parent_taskkill_result},
                        planned_argv=parent_planned_argv,
                        taskkill_result=parent_taskkill_result,
                        notes=all_notes,
                    )

    before = {
        "target": target.to_dict() if target else None,
        "elevated": is_windows_admin() if elevated is None else elevated,
        "stop_parent_tree": stop_parent_tree,
        "parent_pid": parent_pid,
        "parent_planned_argv": list(parent_planned_argv),
    }
    decision, reason = evaluate_stop_listener_policy(
        dry_run=dry_run,
        confirmation=confirmation,
        target=target,
        elevated=elevated,
    )
    planned_argv = build_taskkill_argv(target.pid) if target else tuple()
    taskkill_result: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    mutated = False

    if decision == "ALLOW" and target is not None:
        taskkill_result = execute_taskkill(target.pid, run=run)
        mutated = bool(taskkill_result.get("success"))
        after = {
            "taskkill_result": taskkill_result,
            "target": target.to_dict(),
        }
        if parent_taskkill_result is not None:
            after["parent_taskkill_result"] = parent_taskkill_result
            mutated = mutated and bool(parent_taskkill_result.get("success"))
        if not mutated:
            decision = "BLOCK"
            reason = "taskkill_failed"

    all_notes = (LISTENER_ATTRIBUTION_LIMITATION, *notes)
    return StopListenerResult(
        action_id=ACTION_ID,
        decision=decision,
        dry_run=dry_run,
        mutated=mutated,
        reason=reason,
        target=target,
        before=before,
        after=after,
        planned_argv=planned_argv,
        taskkill_result=taskkill_result,
        notes=all_notes,
    )

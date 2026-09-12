"""Stop-suspected-registry-reverter remediation preview.

Module responsibility:
    Returns a structured preview dict describing the action that would request
    termination of a process suspected of repeatedly re-writing the WinINET
    proxy registry key.  No process signal or termination occurs from this module.

System placement:
    Imported via ``remediation.__init__`` and consumed by the ``remediation``
    CLI command group.  Process termination (if ever permitted by policy) is
    handled exclusively by ``src.proxy_guard.remediation`` behind its safety gate.

Key invariants:
    "Suspected reverter" is a behavioural hypothesis derived from repeated
    registry reappearance signals — it does not constitute proof of malicious
    intent.  The ``blocked_reason`` field reflects default process-kill blocking
    in ``windows_network_toolkit/safety.py``.  Observation ≠ proof.

Side effects:
    Read-only metadata lookup from ``src.proxy_guard.remediation``; no process
    signals or OS calls.

Audit Notes:
    Terminating a suspected reverter process requires corroborating evidence
    (Sysmon Event 13, registry key lineage) before any escalation.  The preview
    result must not be used as a standalone justification for process termination.
"""

from __future__ import annotations

from typing import Any


def preview_stop_reverter(*, pid: int | None = None, dry_run: bool = True) -> dict[str, Any]:
    """Return a preview dict describing the stop-suspected-reverter action.

    Args:
        pid: Optional PID of the process suspected of re-writing the proxy
            registry key.  Included in the output for display; no signal is sent.
        dry_run: Passed through to the ``dry_run`` field; does not affect
            behaviour since no process termination occurs.

    Returns:
        A dict with:

        - ``action_id`` (str): ``"stop_proxy_reverter"``.
        - ``dry_run`` (bool): Reflects the ``dry_run`` argument.
        - ``target_pid`` (int | None): The provided PID, or ``None``.
        - ``risk_level`` (str): Risk classification from the action metadata.
        - ``required_confirmation`` (str): Typed token required for live execution.
        - ``blocked_reason`` (str | None): Policy-level block reason if applicable.
        - ``reversible`` (bool): Whether the action can be undone.

    Side effects:
        Read-only metadata lookup from ``src.proxy_guard.remediation``; no
        process signals.
    """
    from src.proxy_guard.remediation import get_remediation_action

    action = get_remediation_action("stop_proxy_reverter")
    return {
        "action_id": action.action_id,
        "dry_run": dry_run,
        "target_pid": pid,
        "risk_level": action.risk_level,
        "required_confirmation": action.required_confirmation,
        "blocked_reason": action.blocked_reason,
        "reversible": action.reversible,
    }

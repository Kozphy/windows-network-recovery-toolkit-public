"""Stop-proxy-listener remediation preview.

Module responsibility:
    Returns a structured preview dict describing the action that would request
    termination of the process listening on the configured localhost proxy port.
    No process signal or termination occurs from this module.

System placement:
    Imported via ``remediation.__init__`` and consumed by the ``remediation``
    CLI command group.  Process termination (if ever permitted by policy) is
    handled exclusively by ``src.proxy_guard.remediation`` behind its safety gate.

Key invariants:
    Process kill is blocked by default in ``windows_network_toolkit/safety.py``.
    The ``blocked_reason`` field in the returned dict reflects this constraint;
    do not assume the action is executable based on this preview alone.

Side effects:
    Read-only metadata lookup from ``src.proxy_guard.remediation``; no process
    signals or OS calls.

Audit Notes:
    Stopping a proxy listener is a potentially destructive, non-reversible action
    (see ``reversible`` field).  Any execution attempt must be logged, confirmed,
    and corroborated against the active classification before being authorised.
"""

from __future__ import annotations

from typing import Any


def preview_stop_listener(*, pid: int | None = None, dry_run: bool = True) -> dict[str, Any]:
    """Return a preview dict describing the stop-proxy-listener action.

    Args:
        pid: Optional PID of the process to be targeted.  Included in the output
            for display purposes; no signal is sent regardless of this value.
        dry_run: Passed through to the ``dry_run`` field; does not affect
            behaviour since no process termination occurs.

    Returns:
        A dict with:

        - ``action_id`` (str): ``"stop_proxy_listener"``.
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

    action = get_remediation_action("stop_proxy_listener")
    return {
        "action_id": action.action_id,
        "dry_run": dry_run,
        "target_pid": pid,
        "risk_level": action.risk_level,
        "required_confirmation": action.required_confirmation,
        "blocked_reason": action.blocked_reason,
        "reversible": action.reversible,
    }

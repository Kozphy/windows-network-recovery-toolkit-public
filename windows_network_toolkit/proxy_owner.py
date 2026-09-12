"""Process owner detection for localhost proxy port.

Module responsibility:
    Resolve which process listens on the WinINET localhost proxy port (correlation only).

System placement:
    Used by ``proxy-owner`` CLI, ``proxy-health``, and ``watch`` change events.

Key invariants:
    * Listener attribution is not registry writer proof — document in downstream limitations.
    * Returns JSON envelope dict (not ``ProcessOwner`` dataclass) for CLI compatibility.

Side effects:
    Live mode may invoke ``netstat``/process resolution via platform collector.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from src.platform_core.attribution.collector import resolve_listener_process
from src.platform_core.attribution.models import ProcessAttribution
from windows_network_toolkit.models import ProcessOwner
from windows_network_toolkit.proxy_state import collect_proxy_state_model


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def detect_proxy_owner(
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 20.0,
    inject: dict[str, Any] | None = None,
    inject_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return proxy-owner JSON envelope for a localhost listener.

    Args:
        run: Injectable subprocess runner.
        timeout: Resolution timeout seconds.
        inject: Return this dict verbatim (fixture mode).
        inject_state: Fixture proxy state passed to ``collect_proxy_state_model``.

    Returns:
        Dict with ``listener_found``, ``process``, ``localhost_port``, ``errors``.

    Side effects:
        Read-only process/port inspection when not using inject.
    """
    if inject:
        return inject

    run_fn = run or subprocess.run
    state = collect_proxy_state_model(run=run_fn, timeout=timeout, inject=inject_state)
    port = state.localhost_port
    proxy_server = state.wininet_proxy_server
    errors: list[str] = list(state.errors)

    if port is None:
        return {
            "timestamp_utc": _now(),
            "proxy_server": proxy_server,
            "localhost_port": None,
            "listener_found": False,
            "process": None,
            "errors": errors,
        }

    try:
        proc_attr, found = resolve_listener_process(port, run=run_fn, timeout=timeout)
    except Exception as exc:
        errors.append(str(exc))
        return {
            "timestamp_utc": _now(),
            "proxy_server": proxy_server,
            "localhost_port": port,
            "listener_found": False,
            "process": None,
            "errors": errors,
        }

    if not found or proc_attr.pid is None:
        return {
            "timestamp_utc": _now(),
            "proxy_server": proxy_server,
            "localhost_port": port,
            "listener_found": False,
            "process": None,
            "errors": errors,
        }

    owner = _process_owner_from_attribution(proc_attr)
    return {
        "timestamp_utc": _now(),
        "proxy_server": proxy_server,
        "localhost_port": port,
        "listener_found": True,
        "process": {
            "pid": owner.pid,
            "name": owner.name,
            "exe_path": owner.exe_path,
            "cmdline": owner.cmdline,
            "username": owner.username,
        },
        "errors": errors,
    }


def _process_owner_from_attribution(proc: ProcessAttribution) -> ProcessOwner:
    return ProcessOwner(
        listener_found=True,
        pid=proc.pid,
        name=proc.process_name,
        exe_path=proc.executable_path,
        cmdline=proc.command_line,
        username=proc.user_session,
        signed_status=proc.signature_status,
    )

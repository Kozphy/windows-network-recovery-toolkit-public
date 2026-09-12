"""Localhost-aware WinINET listener attribution using netstat/tasklist/PowerShell CIM.

Produces JSON-friendly payloads only; never claims registry write provenance. Command lines are
whatever Windows exposes via CIM and may still be withheld under restricted tokens.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..core.models import ParsedProxy, ProxyRegistrySnapshot
from .owner import attribution_payload


def build_localhost_proxy_attribution(
    reg: ProxyRegistrySnapshot | None,
    parsed: ParsedProxy,
    *,
    run: Callable[..., Any],
    override_port: int | None = None,
) -> dict[str, Any]:
    """Inspect loopback proxy settings and correlate listening PIDs for the proxy port.

    Args:
        reg: Optional registry snapshot (used only for context in output).
        parsed: Parsed ``ProxyServer`` string.
        run: ``subprocess.run`` injector.
        override_port: Optional explicit port (CLI override).

    Returns:
        Structured dict with ``listener_found``, ``owners``, ``attribution_method``, and ``notes``.
    """
    port = override_port if override_port is not None else parsed.localhost_port
    notes: list[str] = [
        "best-effort listener attribution only",
        "registry polling cannot prove which process wrote proxy settings",
    ]

    if not parsed.is_localhost_proxy or port is None:
        return {
            "localhost_proxy_detected": False,
            "localhost_port": None,
            "localhost_host": parsed.localhost_host,
            "listener_found": False,
            "owners": [],
            "attribution_method": "skipped_not_localhost_proxy",
            "notes": notes + ["ProxyServer does not reference a loopback host with a resolvable port."],
            "registry_context": reg.to_dict() if reg is not None else {},
        }

    block = attribution_payload(port, run=run)
    owners = list(block.get("owners") or [])
    o_notes = list(block.get("notes") or [])
    listener_found = bool(owners)

    return {
        "localhost_proxy_detected": True,
        "localhost_port": port,
        "localhost_host": parsed.localhost_host,
        "listener_found": listener_found,
        "owners": owners,
        "attribution_method": "netstat_tasklist_cim",
        "notes": notes + o_notes,
        "registry_context": reg.to_dict() if reg is not None else {},
    }

"""Canonical WinINET (HKCU) proxy state snapshot for watch/diff attribution flows.

Produces JSON-shaped dicts combining ``reg query`` reads and :func:`~src.proxy_guard.parser.parse_proxy_server`
classification. Does not mutate registry or firewall state.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any, Literal

from ..core.models import ProxyRegistrySnapshot
from .parser import ParsedProxy, parse_proxy_server
from .registry import read_proxy_registry

UIProxyMode = Literal["disabled", "manual_localhost", "manual_remote", "pac", "auto_detect", "unknown"]


def _classify_ui_mode(reg: ProxyRegistrySnapshot, parsed: ParsedProxy, is_enabled: bool) -> UIProxyMode:
    """Map registry + parsed proxy into coarse operator-facing mode labels."""
    ac = (reg.auto_config_url or "").strip()
    if ac:
        return "pac"
    if reg.auto_detect == 1:
        return "auto_detect"
    if not is_enabled:
        return "disabled"
    # Enabled manual path
    if parsed.is_localhost_proxy or parsed.proxy_mode in (
        "manual_localhost",
        "http_https_localhost",
        "socks_localhost",
    ):
        return "manual_localhost"
    if parsed.is_missing or parsed.is_malformed:
        return "unknown"
    if parsed.raw and str(parsed.raw).strip():
        return "manual_remote"
    return "unknown"


def snapshot_wininet_state(*, run: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Read HKCU ``Internet Settings`` proxy values and normalized parser overlay.

    Args:
        run: ``subprocess.run`` compliant callable (no ``shell=True``).

    Returns:
        Dict aligned with Proxy Change Attribution schema:
            proxy_enable/proxy_server/auto_config_url/auto_detect/proxy_override/is_enabled plus
            ``parsed_proxy_server`` block with coarse ``proxy_mode`` string bucket.

    Side effects:
        Spawns argv-only ``reg query`` probes only.

    Raises:
        None — registry read helpers return ``None`` fields on failure paths.

    Output guarantees:
        ``parsed_proxy_server.proxy_mode`` is a coarse UX bucket (``disabled``, ``manual_localhost``,
        ``manual_remote``, ``pac``, ``auto_detect``, ``unknown``) derived from registry + parsed string—not the
        low-level ``ProxyMode`` taxonomy in :mod:`~src.proxy_guard.parser` (which distinguishes SOCKS / multi-scheme locals).

    Data handling:
        Unreadable ``reg query`` probes surface as ``None`` sentinel fields inside the merged dict; callers must
        treat ``None`` and missing enable flags as ambiguous offline states inside ``snapshot_wininet_state`` consumers.
    """
    reg = read_proxy_registry(run=run)
    parsed = parse_proxy_server(reg.proxy_server)
    is_enabled = bool(reg.proxy_enable == 1)
    mode = _classify_ui_mode(reg, parsed, is_enabled)

    parsed_block: dict[str, Any] = {
        "raw": parsed.raw,
        "is_localhost_proxy": bool(parsed.is_localhost_proxy),
        "localhost_host": parsed.localhost_host,
        "localhost_port": parsed.localhost_port,
        "proxy_mode": mode,
    }

    return {
        "proxy_enable": reg.proxy_enable,
        "proxy_server": reg.proxy_server,
        "auto_config_url": reg.auto_config_url,
        "auto_detect": reg.auto_detect,
        "proxy_override": reg.proxy_override,
        "is_enabled": is_enabled,
        "parsed_proxy_server": parsed_block,
    }

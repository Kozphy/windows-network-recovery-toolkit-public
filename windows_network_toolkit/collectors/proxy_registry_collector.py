"""WinINET HKCU proxy registry collector facade — delegates to src/proxy_guard/registry.

Module responsibility:
    Read the five core WinINET Internet Settings registry values
    (ProxyEnable, ProxyServer, AutoConfigURL, ProxyOverride, AutoDetect) from
    HKCU and return a normalised evidence dict.  Accepts an injectable ``run``
    callable so tests can exercise this path without a Windows host.

System placement:
    Called by ``proxy_state.collect_dashboard_proxy_state`` and the analytics
    pipeline's signal-collection phase.  The actual registry read lives in
    ``src.proxy_guard.registry.read_proxy_registry``; this module only
    dispatches and shapes the output.

Key invariants:
    * Never writes the registry.
    * All five keys are always present in the returned dict (values may be
      ``None`` when the key is absent or unset).
    * ``source`` is always ``"hkcu_internet_settings"``.

Side effects:
    Reads HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings
    when called without an injectable ``run`` override (Windows only).

Failure modes:
    ``read_proxy_registry`` exceptions propagate to the caller.  On
    non-Windows hosts the underlying implementation may raise or return empty
    values — callers should handle accordingly.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def collect_proxy_registry(
    *,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Read WinINET HKCU Internet Settings proxy registry state.

    Delegates to ``read_proxy_registry`` in ``src.proxy_guard.registry``.
    This is a Windows-only live read; pass ``run`` in tests to inject a
    fixture subprocess runner.

    Args:
        run: Optional subprocess runner forwarded to the underlying registry
            reader.  Enables deterministic fixture tests on non-Windows hosts.

    Returns:
        Dict with keys ``proxy_enable``, ``proxy_server``,
        ``auto_config_url``, ``proxy_override``, ``auto_detect``, and
        ``source`` (``"hkcu_internet_settings"``).
    """
    from src.proxy_guard.registry import read_proxy_registry

    kwargs: dict[str, Any] = {}
    if run is not None:
        kwargs["run"] = run
    snap = read_proxy_registry(**kwargs)
    return {
        "proxy_enable": snap.proxy_enable,
        "proxy_server": snap.proxy_server,
        "auto_config_url": snap.auto_config_url,
        "proxy_override": snap.proxy_override,
        "auto_detect": snap.auto_detect,
        "source": "hkcu_internet_settings",
    }

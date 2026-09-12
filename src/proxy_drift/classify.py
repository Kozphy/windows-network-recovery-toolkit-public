"""Ordinal classification for proxy drift observations (not accusations)."""

from __future__ import annotations

from typing import Any

from src.proxy_guard.parser import parse_proxy_server

_DEV_PROCESS_FRAGMENTS = frozenset(
    {"node.exe", "cursor.exe", "code.exe", "electron", "python.exe", "powershell.exe", "cmd.exe"}
)
_VPN_FRAGMENTS = frozenset(
    {"hide.me", "hideme", "openvpn", "wireguard", "nordvpn", "expressvpn", "vpn", "tailscale"}
)

LIMITATIONS = [
    "Classification is triage guidance — not malware verdict or registry writer proof.",
    "Listener correlation does not prove which process wrote ProxyEnable/ProxyServer.",
]


def _name_hints(process_name: str | None, command: str | None) -> tuple[bool, bool]:
    blob = f"{process_name or ''} {command or ''}".lower()
    dev = any(f in blob for f in _DEV_PROCESS_FRAGMENTS)
    vpn = any(f in blob for f in _VPN_FRAGMENTS)
    return dev, vpn


def classify_proxy_drift(
    *,
    proxy_enable: int | None,
    proxy_server: str | None,
    auto_config_url: str | None = None,
    winhttp_direct: bool | None = None,
    listener_found: bool | None = None,
    listener_exited: bool = False,
    process_name: str | None = None,
    command_line: str | None = None,
    proxy_probe_ok: bool | None = None,
    direct_probe_ok: bool | None = None,
) -> dict[str, Any]:
    """Return classification label and governance-safe rationale.

    Optional ``proxy_probe_ok`` / ``direct_probe_ok`` refine listener-up cases:
    listener present + proxy path fail + direct HTTPS ok → ``BROKEN_LOCALHOST_PROXY``.
    """
    parsed = parse_proxy_server(proxy_server)
    enabled = int(proxy_enable or 0) == 1
    dev_hint, vpn_hint = _name_hints(process_name, command_line)

    if auto_config_url and str(auto_config_url).strip():
        label = "PAC_CONFIGURED"
        rationale = "AutoConfigURL is set; PAC path requires separate validation."
    elif not enabled and not parsed.raw:
        label = "NO_PROXY"
        rationale = "WinINET proxy disabled with no ProxyServer value."
    elif enabled and not parsed.is_localhost_proxy and parsed.raw:
        label = "INSUFFICIENT_EVIDENCE"
        rationale = "Non-localhost proxy configured; corporate proxy policy may apply — do not auto-clear."
    elif (
        enabled
        and parsed.is_localhost_proxy
        and listener_found is True
        and proxy_probe_ok is False
        and direct_probe_ok is True
    ):
        label = "BROKEN_LOCALHOST_PROXY"
        rationale = (
            "Localhost listener is present but the proxy path failed while direct HTTPS works "
            "(active-but-broken — prefer-direct clear is appropriate)."
        )
    elif enabled and parsed.is_localhost_proxy and listener_found is True:
        if vpn_hint:
            label = "KNOWN_VPN_PROXY"
        elif dev_hint:
            label = "KNOWN_DEV_PROXY"
        else:
            label = "LOCAL_PROXY_ACTIVE"
        rationale = "Localhost proxy enabled with an active listener on the configured port."
        if proxy_probe_ok is False and direct_probe_ok is False:
            rationale += " Proxy and direct HTTPS probes both failed — path triage inconclusive."
    elif enabled and parsed.is_localhost_proxy and listener_found is False:
        if listener_exited:
            label = "STALE_PROXY_AFTER_PROCESS_EXIT"
            rationale = "Proxy still points at localhost after listener disappeared."
        else:
            label = "STALE_LOCALHOST_PROXY"
            rationale = (
                "ProxyEnable=1 toward localhost but no listener — likely ERR_PROXY_CONNECTION_FAILED."
            )
    elif enabled and parsed.is_localhost_proxy and listener_found is None:
        label = "UNKNOWN_LOCAL_PROXY"
        rationale = "Localhost proxy configured; listener state unknown at probe time."
    elif winhttp_direct is False and enabled:
        label = "WINHTTP_WININET_MISMATCH"
        rationale = "WinINET proxy enabled while WinHTTP reports non-direct access."
    else:
        label = "INSUFFICIENT_EVIDENCE"
        rationale = "Insufficient contrasting evidence for a stronger label."

    return {
        "classification": label,
        "rationale": rationale,
        "localhost_port": parsed.localhost_port,
        "is_localhost_proxy": parsed.is_localhost_proxy,
        "limitations": list(LIMITATIONS),
    }

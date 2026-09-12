"""Classify localhost proxy listeners — observation only, not guilt."""

from __future__ import annotations

import re

from .models import ListenerClassification, ProcessAttribution, ProxyStateSnapshot

_DEV_NAMES = frozenset(
    {"node.exe", "node", "python.exe", "python", "java.exe", "dotnet.exe", "wsl.exe"}
)
_SECURITY_NAMES = frozenset(
    {"zscaler.exe", "csagent.exe", "forticlient.exe", "vpnagent.exe", "nessusagent.exe"}
)
_VPN_NAMES = frozenset(
    {"openvpn.exe", "wireguard.exe", "nordvpn.exe", "expressvpn.exe", "pulse.exe"}
)
_SUSPICIOUS_TERMS = re.compile(
    r"(mitm|inject|proxy.?tool|fiddler|charles|burp|socks|tunnel.?proxy)",
    re.I,
)


def classify_listener(
    proxy: ProxyStateSnapshot,
    process: ProcessAttribution,
    *,
    listener_detected: bool,
) -> tuple[ListenerClassification, str, list[str]]:
    """Classify listener.

    Args:
        proxy: proxy supplied by the caller.
        process: process supplied by the caller.
        listener_detected: listener detected supplied by the caller.

    Returns:
        The computed `tuple[ListenerClassification, str, list[str]]` value.

    Side effects:
        None.
    """
    limitations = [
        "Listener classification is correlation, not registry-writer proof.",
        "Publisher/signature absence does not imply malicious intent.",
    ]
    if proxy.wininet_proxy_enable != 1 and not proxy.wininet_proxy_server:
        return (
            ListenerClassification.NO_PROXY,
            "WinINET proxy disabled and no ProxyServer configured.",
            limitations,
        )

    if proxy.wininet_proxy_enable == 1 and proxy.wininet_proxy_server:
        if not re.search(r"127(?:\.\d{1,3}){3}|localhost", proxy.wininet_proxy_server, re.I):
            return (
                ListenerClassification.POSSIBLE_MITM_RISK,
                f"ProxyServer points to non-localhost endpoint: {proxy.wininet_proxy_server}.",
                limitations + ["External proxy may be legitimate VPN or corporate gateway — verify policy."],
            )

    port = proxy.localhost_port
    if port and proxy.wininet_proxy_enable == 1 and not listener_detected:
        return (
            ListenerClassification.DEAD_PROXY_CONFIG,
            f"ProxyServer references localhost:{port} but no listener is bound.",
            limitations + ["Dead localhost proxy often causes ERR_PROXY_CONNECTION_FAILED."],
        )

    if not listener_detected:
        if proxy.wininet_proxy_enable == 1:
            return (
                ListenerClassification.UNKNOWN_LOCAL_PROXY,
                "Proxy enabled but no localhost listener resolved.",
                limitations,
            )
        return ListenerClassification.NO_PROXY, "No active localhost proxy listener.", limitations

    name = (process.process_name or "").lower()
    cmd = process.command_line or ""

    if name in _DEV_NAMES or "dev-server" in cmd.lower() or "webpack" in cmd.lower():
        return (
            ListenerClassification.KNOWN_DEV_PROXY,
            f"Development proxy pattern matched: {process.process_name}.",
            limitations,
        )
    if name in _SECURITY_NAMES:
        return (
            ListenerClassification.KNOWN_SECURITY_TOOL,
            f"Known security agent proxy: {process.process_name}.",
            limitations,
        )
    if name in _VPN_NAMES or "vpn" in name:
        return (
            ListenerClassification.KNOWN_VPN_PROXY,
            f"VPN-related proxy process: {process.process_name}.",
            limitations,
        )
    if _SUSPICIOUS_TERMS.search(cmd) or _SUSPICIOUS_TERMS.search(name):
        return (
            ListenerClassification.SUSPICIOUS_PROXY,
            "Command line or name matches suspicious proxy tooling keywords.",
            limitations + ["Suspicious classification requires human review; not malware verdict."],
        )
    return (
        ListenerClassification.UNKNOWN_LOCAL_PROXY,
        f"Localhost listener on proxy port owned by {process.process_name or 'unknown'}.",
        limitations,
    )

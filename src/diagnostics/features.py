"""Immutable ``FeatureVector`` schema bridging collectors and deterministic scoring.

All fields map to primitive JSON types via `FeatureVector.to_dict` / ``from_dict``
for fixtures and audit snapshots (no secrets or payloads).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FeatureVector:
    """Normalized feature schema consumed by decision scoring.

    Attributes:
        ping_ip_ok: ICMP reachability to public numeric IP.
        ping_domain_ok: ICMP reachability to public domain name.
        nslookup_ok: DNS resolver success status.
        tcp_443_ok: TCP 443 reachability status.
        browser_http_ok: HTTPS probe success status.
        proxy_enabled: Combined proxy-enabled indicator.
        winhttp_proxy_enabled: WinHTTP proxy-enabled indicator.
        dns_servers_detected: Count of DNS server entries observed.
        adapter_connected: Physical adapter up/down signal.
        gateway_reachable: Gateway ping status (`None` if unknown).
        tls_cert_issue_detected: TLS/certificate issue heuristic signal.
        firewall_path_suspected: Firewall/filtering suspicion heuristic signal.
        time_wait_count: TIME_WAIT socket count.
        established_count: ESTABLISHED socket count.
    """

    ping_ip_ok: bool
    ping_domain_ok: bool
    nslookup_ok: bool
    tcp_443_ok: bool
    browser_http_ok: bool
    proxy_enabled: bool
    winhttp_proxy_enabled: bool
    dns_servers_detected: int
    adapter_connected: bool
    gateway_reachable: bool | None
    tls_cert_issue_detected: bool
    firewall_path_suspected: bool
    time_wait_count: int
    established_count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize feature vector into JSON-friendly mapping."""
        return {
            "ping_ip_ok": self.ping_ip_ok,
            "ping_domain_ok": self.ping_domain_ok,
            "nslookup_ok": self.nslookup_ok,
            "tcp_443_ok": self.tcp_443_ok,
            "browser_http_ok": self.browser_http_ok,
            "proxy_enabled": self.proxy_enabled,
            "winhttp_proxy_enabled": self.winhttp_proxy_enabled,
            "dns_servers_detected": self.dns_servers_detected,
            "adapter_connected": self.adapter_connected,
            "gateway_reachable": self.gateway_reachable,
            "tls_cert_issue_detected": self.tls_cert_issue_detected,
            "firewall_path_suspected": self.firewall_path_suspected,
            "time_wait_count": self.time_wait_count,
            "established_count": self.established_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeatureVector:
        """Create feature vector from mapping with conservative defaults.

        Args:
            data: Source mapping from collector payload or fixture.

        Returns:
            FeatureVector: Normalized feature vector instance.

        Raises:
            KeyError: If ``ping_ip_ok``, ``nslookup_ok``, or ``browser_http_ok``
                are absent (these are required indexed keys).
            ValueError: If ``dns_servers_detected``, ``time_wait_count``, or
                ``established_count`` cannot be coerced with ``int()``.
        """
        gw = data.get("gateway_reachable")
        if gw is not None and not isinstance(gw, bool):
            gw = bool(gw)
        return cls(
            ping_ip_ok=bool(data["ping_ip_ok"]),
            ping_domain_ok=bool(data.get("ping_domain_ok", False)),
            nslookup_ok=bool(data["nslookup_ok"]),
            tcp_443_ok=bool(data.get("tcp_443_ok", False)),
            browser_http_ok=bool(data["browser_http_ok"]),
            proxy_enabled=bool(data.get("proxy_enabled", False)),
            winhttp_proxy_enabled=bool(data.get("winhttp_proxy_enabled", False)),
            dns_servers_detected=int(data.get("dns_servers_detected", 0)),
            adapter_connected=bool(data.get("adapter_connected", True)),
            gateway_reachable=gw,  # type: ignore[arg-type]
            tls_cert_issue_detected=bool(data.get("tls_cert_issue_detected", False)),
            firewall_path_suspected=bool(data.get("firewall_path_suspected", False)),
            time_wait_count=int(data.get("time_wait_count", 0)),
            established_count=int(data.get("established_count", 0)),
        )

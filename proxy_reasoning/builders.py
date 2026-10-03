"""Build ProxyEntity and signals from collector payloads (backward compatible).

Module responsibility:
    Translate ``proxy_guard``/CLI-shaped dicts into canonical ``ProxySignal`` and ``ProxyEntity``
    models, applying classification helpers.

Input assumptions:
    Payload keys mirror live snapshot collectors (``proxy_enable``, ``proxy_server``, probes).

Side effects:
    None.
"""

from __future__ import annotations

from typing import Any

from proxy_reasoning.classification import apply_attribution_limitations, classify_trust_risk
from proxy_reasoning.models import (
    BehavioralAttributes,
    ConfigurationAttributes,
    NetworkAttributes,
    ProcessAttributionAttributes,
    ProxyEntity,
    ProxySignal,
)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "on", "enabled"}
    return bool(value)


def signals_from_dict(payload: dict[str, Any], *, source: str = "collector") -> list[ProxySignal]:
    """Flatten a collector dict into named signals."""
    observed_at = str(payload.get("observed_at") or payload.get("timestamp") or "")
    signals: list[ProxySignal] = []

    def add(name: str, value: Any) -> None:
        if value is not None:
            signals.append(
                ProxySignal(name=name, value=value, source=source, observed_at=observed_at)
            )

    # Registry / config
    wininet = payload.get("wininet") or payload.get("user_proxy") or {}
    if isinstance(wininet, dict):
        add(
            "wininet_proxy_enabled",
            _truthy(wininet.get("ProxyEnable") or wininet.get("proxy_enable")),
        )
        add(
            "proxy_server_localhost",
            _truthy(wininet.get("is_localhost") or wininet.get("localhost_proxy")),
        )
        proxy_server = wininet.get("ProxyServer") or wininet.get("proxy_server")
        if proxy_server:
            add("proxy_server", proxy_server)
    add("wininet_proxy_enabled", payload.get("wininet_proxy_enabled"))
    add("proxy_server_localhost", payload.get("proxy_server_localhost"))
    add("is_loopback_proxy", payload.get("is_loopback_proxy"))
    add("wininet_winhttp_divergent", payload.get("wininet_winhttp_divergent"))
    add("winhttp_direct", payload.get("winhttp_direct"))

    # Connectivity
    for key in (
        "ping_ok",
        "dns_ok",
        "tcp_443_ok",
        "curl_https_ok",
        "browser_https_ok",
        "browser_https_failed",
        "browser_works",
        "proxy_bypass_succeeded",
        "proxied_path_failed",
    ):
        add(key, payload.get(key))

    # Listener / process
    listener = payload.get("listener") or payload.get("port_owner") or {}
    if isinstance(listener, dict):
        add("listener_on_proxy_port", _truthy(listener.get("listening") or listener.get("present")))
        add("listener_process_name", listener.get("process_name") or listener.get("name"))
        add("listener_pid", listener.get("pid"))
    add("listener_on_proxy_port", payload.get("listener_on_proxy_port"))
    add("listener_process_name", payload.get("listener_process_name"))

    # App / firewall feedback
    add("electron_app_failed", payload.get("electron_app_failed"))
    add("app_fails", payload.get("app_fails"))
    add("firewall_reset_helped", payload.get("firewall_reset_helped"))
    add("electron_app_failed_before", payload.get("electron_app_failed_before"))

    # Risk hints from MITM scan
    add("suspicious_cert_observed", payload.get("suspicious_cert_observed"))
    add("unexpected_persistence", payload.get("unexpected_persistence"))

    return signals


def build_proxy_entity(
    payload: dict[str, Any],
    *,
    suspicious_cert_observed: bool | None = None,
    unexpected_persistence: bool | None = None,
) -> ProxyEntity:
    """Construct a ProxyEntity from a scan/collector payload."""
    wininet = payload.get("wininet") or payload.get("user_proxy") or {}
    winhttp = payload.get("winhttp") or {}
    listener = payload.get("listener") or payload.get("port_owner") or {}
    parsed = payload.get("parsed_proxy") or {}

    proxy_enable = payload.get("proxy_enable")
    if proxy_enable is None and isinstance(wininet, dict):
        proxy_enable = wininet.get("ProxyEnable")
    proxy_server = payload.get("proxy_server")
    if proxy_server is None and isinstance(wininet, dict):
        proxy_server = wininet.get("ProxyServer")

    is_loopback = bool(
        payload.get("is_loopback_proxy")
        or parsed.get("is_localhost_proxy")
        or payload.get("proxy_server_localhost"),
    )
    host = payload.get("host") or parsed.get("localhost_host")
    port = payload.get("port") or parsed.get("localhost_port")

    proc_name = payload.get("process_name") or listener.get("process_name") or listener.get("name")
    proc_path = (
        payload.get("executable_path") or listener.get("executable_path") or listener.get("path")
    )

    cfg = ConfigurationAttributes(
        source=payload.get("config_source") or "WinINET",
        proxy_enable=_truthy(proxy_enable) if proxy_enable is not None else None,
        proxy_server=str(proxy_server) if proxy_server else None,
        autoconfig_url=(wininet.get("AutoConfigURL") if isinstance(wininet, dict) else None),
        bypass_list=(wininet.get("ProxyOverride") if isinstance(wininet, dict) else None),
        scope="user",
        observed_at=str(payload.get("observed_at") or payload.get("timestamp") or ""),
        winhttp_direct=_truthy(winhttp.get("direct"))
        if isinstance(winhttp, dict)
        else payload.get("winhttp_direct"),
        wininet_winhttp_divergent=payload.get("wininet_winhttp_divergent"),
    )

    net = NetworkAttributes(
        host=str(host) if host else None,
        port=int(port) if port is not None else None,
        is_loopback=is_loopback,
        is_remote=bool(host and not is_loopback),
        dns_resolution_state="ok" if _truthy(payload.get("dns_ok")) else "unknown",
        tcp_reachability="ok" if _truthy(payload.get("tcp_443_ok")) else "unknown",
        tls_behavior="ok" if _truthy(payload.get("curl_https_ok")) else "unknown",
        listener_present=_truthy(listener.get("listening") or listener.get("present"))
        if isinstance(listener, dict)
        else payload.get("listener_on_proxy_port"),
    )

    proc = apply_attribution_limitations(
        ProcessAttributionAttributes(
            pid=listener.get("pid") if isinstance(listener, dict) else payload.get("pid"),
            process_name=str(proc_name).lower() if proc_name else None,
            executable_path=str(proc_path) if proc_path else None,
            command_line=listener.get("command_line") if isinstance(listener, dict) else None,
            parent_pid=listener.get("parent_pid") if isinstance(listener, dict) else None,
            attribution_confidence="medium" if proc_name else "low",
        ),
    )

    beh = BehavioralAttributes(
        affects_browser=payload.get("affects_browser"),
        affects_electron_apps=payload.get("affects_electron_apps"),
        curl_works=payload.get("curl_https_ok"),
        browser_works=payload.get("browser_works"),
        app_fails=payload.get("app_fails") or payload.get("electron_app_failed"),
        firewall_reset_helped=payload.get("firewall_reset_helped"),
    )

    cert_flag = (
        suspicious_cert_observed
        if suspicious_cert_observed is not None
        else _truthy(
            payload.get("suspicious_cert_observed"),
        )
    )
    persist_flag = (
        unexpected_persistence
        if unexpected_persistence is not None
        else _truthy(
            payload.get("unexpected_persistence"),
        )
    )

    entity = ProxyEntity(
        configuration_attributes=cfg,
        network_attributes=net,
        process_attribution_attributes=proc,
        behavioral_attributes=beh,
    )
    entity = entity.model_copy(
        update={
            "trust_risk_attributes": classify_trust_risk(
                entity, suspicious_cert_observed=cert_flag, unexpected_persistence=persist_flag
            )
        },
    )
    return entity

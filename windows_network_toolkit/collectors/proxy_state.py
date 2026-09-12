"""Immutable WinINET HKCU proxy state for the local monitoring dashboard.

Module responsibility:
    Read ProxyEnable / ProxyServer / AutoConfigURL / AutoDetect via the existing
    registry collector facade and normalize localhost host/port parsing.

System placement:
    Fed into ``ProxyWatcher`` change detection and dashboard Overview cards.

Key invariants:
    * Never writes the registry.
    * ``identity_tuple`` excludes timestamp so polling can detect real key changes.
    * ``timestamp_utc`` uses UTC with a trailing ``Z``.

Side effects:
    * Registry read via ``collect_proxy_registry`` (unless inject provided).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from windows_network_toolkit.collectors.proxy_registry_collector import collect_proxy_registry


@dataclass(frozen=True)
class DashboardProxyState:
    """Typed immutable snapshot of HKCU Internet Settings proxy keys."""

    proxy_enable: int | None
    proxy_server: str | None
    auto_config_url: str | None
    auto_detect: int | None
    proxy_override: str | None
    is_enabled: bool
    is_localhost_proxy: bool
    localhost_host: str | None
    localhost_port: int | None
    source: str
    timestamp_utc: str
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialise the proxy state snapshot to a plain dict safe for JSON output."""
        return {
            "proxy_enable": self.proxy_enable,
            "proxy_server": self.proxy_server,
            "auto_config_url": self.auto_config_url,
            "auto_detect": self.auto_detect,
            "proxy_override": self.proxy_override,
            "is_enabled": self.is_enabled,
            "is_localhost_proxy": self.is_localhost_proxy,
            "localhost_host": self.localhost_host,
            "localhost_port": self.localhost_port,
            "source": self.source,
            "timestamp_utc": self.timestamp_utc,
            "errors": list(self.errors),
        }

    def identity_tuple(self) -> tuple[Any, ...]:
        """Comparable tuple for change detection (excludes timestamp)."""

        return (
            self.proxy_enable,
            self.proxy_server,
            self.auto_config_url,
            self.auto_detect,
            self.proxy_override,
        )


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string with a ``Z`` suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_localhost_proxy_server(proxy_server: str | None) -> tuple[bool, str | None, int | None]:
    """Parse localhost host/port from ProxyServer (IPv4, localhost, [::1]).

    Returns:
        ``(is_localhost, host, port)``.
    """

    if not proxy_server or not str(proxy_server).strip():
        return False, None, None
    raw = str(proxy_server).strip()
    # Prefer existing parser when available
    try:
        from src.proxy_guard.parser import parse_proxy_server

        parsed = parse_proxy_server(raw)
        if parsed.is_localhost_proxy:
            return True, parsed.localhost_host or "127.0.0.1", parsed.localhost_port
    except Exception:  # noqa: BLE001 — fall through to regex
        pass

    # Explicit IPv6 [::1]:port
    m6 = re.search(r"\[::1\]:(\d{1,5})", raw, re.I)
    if m6:
        return True, "::1", int(m6.group(1))
    m4 = re.search(r"(?:127(?:\.\d{1,3}){3}|localhost):(\d{1,5})", raw, re.I)
    if m4:
        host = (
            "localhost"
            if "localhost" in raw.lower()
            else re.search(r"127(?:\.\d{1,3}){3}", raw, re.I)
        )
        return True, (host.group(0) if hasattr(host, "group") else "127.0.0.1"), int(m4.group(1))
    if re.search(r"127(?:\.\d{1,3}){3}|localhost|::1", raw, re.I):
        return True, "127.0.0.1", None
    return False, None, None


def collect_dashboard_proxy_state(
    *,
    run: Callable[..., Any] | None = None,
    inject: dict[str, Any] | None = None,
) -> DashboardProxyState:
    """Collect an immutable HKCU proxy snapshot for the dashboard.

    Args:
        run: Optional subprocess runner forwarded to ``collect_proxy_registry``.
        inject: Optional raw dict skipping live registry reads (tests/fixtures).

    Returns:
        ``DashboardProxyState``. Missing/malformed registry values become ``None``;
        collector exceptions soft-fail into ``errors``.

    Side effects:
        Registry read when ``inject`` is absent; never writes.
    """

    errors: list[str] = []
    if inject is not None:
        raw = dict(inject)
    else:
        try:
            raw = collect_proxy_registry(run=run)
        except Exception as exc:  # noqa: BLE001 — soft-fail collector
            errors.append(str(exc))
            raw = {}

    enable = raw.get("proxy_enable")
    try:
        enable_i = int(enable) if enable is not None else None
    except (TypeError, ValueError):
        enable_i = None
        errors.append("proxy_enable_unparseable")

    auto_detect = raw.get("auto_detect")
    try:
        auto_i = int(auto_detect) if auto_detect is not None else None
    except (TypeError, ValueError):
        auto_i = None

    server = raw.get("proxy_server")
    server_s = str(server) if server is not None and str(server).strip() else None
    pac = raw.get("auto_config_url")
    pac_s = str(pac) if pac is not None and str(pac).strip() else None
    override = raw.get("proxy_override")
    override_s = str(override) if override is not None else None

    is_local, host, port = parse_localhost_proxy_server(server_s)
    return DashboardProxyState(
        proxy_enable=enable_i,
        proxy_server=server_s,
        auto_config_url=pac_s,
        auto_detect=auto_i,
        proxy_override=override_s,
        is_enabled=bool(enable_i == 1),
        is_localhost_proxy=is_local,
        localhost_host=host,
        localhost_port=port,
        source=str(raw.get("source") or "hkcu_internet_settings"),
        timestamp_utc=_now(),
        errors=tuple(errors),
    )

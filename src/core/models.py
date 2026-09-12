"""Immutable dataclasses for WinINET HKCU snapshots, parsed proxy strings, and live correlate payloads.

Module responsibility:
    Define JSON-serializable frozen records shared by ``src.observability``, ``src.diagnostics``, and replay
    tooling so hypothesis engines consume stable field names without dict sprawl.

System placement:
    Consumed downstream by ``LiveNetworkSnapshot`` assembly, ``reports/snapshots/*.json`` persistence, and replay
    hydrators such as ``src.audit.replay.live_network_snapshot_from_observations`` for ``observations`` blobs.

Schema / timestamps:
    ``generated_at_utc`` strings follow ``utc_now_iso`` formatting from callers (UTC-aware ISO-like text).

Validation boundaries:
    Parsers coerce missing registry values to sentinel flags (`is_missing`, ``proxy_mode='missing'`); callers
    must not assume benign defaults imply healthy connectivity.

Key invariants:
    Dataclasses are frozen; transformations happen via constructors or dedicated builders—mutations require new
    instances.

Audit Notes:
    When attributing proxies, correlate ``ParsedProxy.localhost_port`` with ``LiveNetworkSnapshot.port_owners``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from ..diagnostics.features import FeatureVector

ProxyMode = Literal[
    "missing",
    "malformed",
    "disabled_server_field",
    "manual_localhost",
    "manual_explicit",
    "socks_localhost",
    "http_https_localhost",
    "multi_scheme_explicit",
]


@dataclass(frozen=True)
class ParsedProxy:
    """Normalized parse of HKCU ``ProxyServer`` (and derived flags).

    Parsing is pure ASCII/UTF-8 string logic; callers combine with ``ProxyEnable``.
    """

    raw: str | None
    is_missing: bool
    is_malformed: bool
    is_localhost_proxy: bool
    localhost_host: str | None
    localhost_port: int | None
    proxy_mode: ProxyMode
    socks_port: int | None
    http_localhost_port: int | None
    https_localhost_port: int | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize parser output for JSON artefacts and API bridges."""
        return {
            "raw": self.raw,
            "is_missing": self.is_missing,
            "is_malformed": self.is_malformed,
            "is_localhost_proxy": self.is_localhost_proxy,
            "localhost_host": self.localhost_host,
            "localhost_port": self.localhost_port,
            "proxy_mode": self.proxy_mode,
            "socks_port": self.socks_port,
            "http_localhost_port": self.http_localhost_port,
            "https_localhost_port": self.https_localhost_port,
        }


@dataclass(frozen=True)
class ProxyRegistrySnapshot:
    """HKCU Internet Settings proxy-related values (numeric + string fields)."""

    proxy_enable: int | None
    proxy_server: str | None
    auto_config_url: str | None
    auto_detect: int | None
    proxy_override: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return registry fields plus ``is_enabled`` boolean (``ProxyEnable == 1``)."""
        enabled = self.proxy_enable == 1
        return {
            "proxy_enable": self.proxy_enable,
            "proxy_server": self.proxy_server,
            "auto_config_url": self.auto_config_url,
            "auto_detect": self.auto_detect,
            "proxy_override": self.proxy_override,
            "is_enabled": enabled,
        }


@dataclass(frozen=True)
class PortOwnerRecord:
    """Best-effort TCP listener / connection owner (may be permission-limited)."""

    port: int
    pid: int | None
    process_name: str | None
    state: str | None
    local_address: str | None
    parent_pid: int | None
    parent_name: str | None
    command_line: str | None
    executable_path: str | None
    permission_limited: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize listener attribution without duplicating outer ``port`` key in CLI."""
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "state": self.state,
            "local_address": self.local_address,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "command_line": self.command_line,
            "executable_path": self.executable_path,
            "permission_limited": self.permission_limited,
        }


@dataclass(frozen=True)
class LiveNetworkSnapshot:
    """Structured observability bundle for live diagnosis (v2 engine)."""

    generated_at_utc: str
    feature_vector: FeatureVector
    proxy_registry: ProxyRegistrySnapshot
    parsed_proxy: ParsedProxy
    port_owners: tuple[PortOwnerRecord, ...] = ()
    localhost_listen_ports: tuple[int, ...] = ()
    interesting_processes: tuple[dict[str, Any], ...] = ()
    tcp_top_ports: tuple[dict[str, Any], ...] = ()
    commands_executed: tuple[dict[str, str], ...] = ()
    permission_notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Flatten snapshot for on-disk JSON including combined proxy flags for audits."""
        reg = self.proxy_registry.to_dict()
        pp = self.parsed_proxy.to_dict()
        is_local = bool(pp.get("is_localhost_proxy"))
        port = pp.get("localhost_port")
        return {
            "generated_at_utc": self.generated_at_utc,
            "feature_vector": self.feature_vector.to_dict(),
            "user_proxy_registry": self.proxy_registry.to_dict(),
            "parsed_proxy_server": pp,
            "combined_proxy_flags": {
                **reg,
                "is_localhost_proxy": is_local,
                "localhost_port": port,
                "proxy_mode": self.parsed_proxy.proxy_mode,
            },
            "port_attribution": {
                "owners": [{"port": o.port, **o.to_dict()} for o in self.port_owners],
            },
            "localhost_listen_ports": list(self.localhost_listen_ports),
            "interesting_processes": list(self.interesting_processes),
            "tcp_top_ports_by_count": list(self.tcp_top_ports),
            "commands_executed": list(self.commands_executed),
            "permission_notes": list(self.permission_notes),
        }


def registry_with_parsed(
    snapshot: ProxyRegistrySnapshot,
    parsed: ParsedProxy,
) -> dict[str, Any]:
    """Merge registry + parsed server into CLI/audit-friendly mapping."""
    d = snapshot.to_dict()
    parsed_d = parsed.to_dict()
    d["parsed_proxy_server"] = parsed_d
    d["is_localhost_proxy"] = parsed.is_localhost_proxy
    d["localhost_host"] = parsed.localhost_host
    d["localhost_port"] = parsed.localhost_port
    d["proxy_mode"] = parsed.proxy_mode
    return d

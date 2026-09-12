"""Linux / Debian / Ubuntu / WSL read-only network diagnostics."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from platform_core.network_diagnostics.base import (
    NetworkDiagnosticsProvider,
    detect_linux_distro,
    dns_observation,
    observation,
)
from platform_core.network_diagnostics.listeners import listening_port_observations


class LinuxNetworkDiagnostics(NetworkDiagnosticsProvider):
    """Observe-only diagnostics for Linux hosts and WSL."""

    def os_family(self) -> str:
        """Provide os family behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return "linux"

    def live_remediation_supported(self) -> bool:
        """Provide live remediation supported behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return False

    def limitations(self) -> list[str]:
        """Provide limitations behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        notes = [
            "Linux path is observe-only; registry/proxy remediation stays on Windows agents.",
            "Listener correlation is candidate evidence, not registry-writer proof.",
        ]
        if detect_linux_distro() == "wsl":
            notes.append(
                "WSL shares Windows network stack for some paths; label observations separately."
            )
        return notes

    def collect_observations(self) -> list[dict[str, Any]]:
        """Collect observations for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May read local system, file, or network state through configured providers.
        """
        rows: list[dict[str, Any]] = [
            observation("os_family", "linux", source="network_diagnostics.linux"),
            observation("linux_distro", detect_linux_distro(), source="network_diagnostics.linux"),
            observation("hostname", socket.gethostname(), source="network_diagnostics.linux"),
            dns_observation(),
        ]
        try:
            from src.proxy_guard.linux_proxy_snapshot import collect_linux_proxy_snapshot

            snap = collect_linux_proxy_snapshot(skip_optional_cli=True)
            proxy_lim = list(snap.limitations) if snap.limitations else None
            rows.append(
                observation(
                    "linux_proxy_configured",
                    snap.proxy_configured(),
                    source="network_diagnostics.linux",
                    limitations=proxy_lim,
                )
            )
            rows.append(
                observation(
                    "linux_proxy_sources",
                    ",".join(snap.sources) or "none",
                    source="network_diagnostics.linux",
                )
            )
            if snap.environment:
                rows.append(
                    observation(
                        "linux_proxy_env_summary",
                        json.dumps(snap.environment, sort_keys=True),
                        source="network_diagnostics.linux",
                    )
                )
        except Exception as exc:  # noqa: BLE001 — observe-only path must not fail diagnostics
            rows.append(
                observation(
                    "linux_proxy_snapshot_error",
                    str(exc),
                    source="network_diagnostics.linux",
                    limitations=["linux_proxy_snapshot_unavailable"],
                )
            )
        try:
            route = Path("/proc/net/route").read_text(encoding="utf-8", errors="ignore")
            rows.append(
                observation(
                    "proc_net_route_present",
                    bool(route.strip()),
                    source="network_diagnostics.linux",
                )
            )
        except OSError:
            rows.append(
                observation(
                    "proc_net_route_present",
                    False,
                    source="network_diagnostics.linux",
                    limitations=["procfs_unavailable"],
                )
            )
        try:
            resolv = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore")
            rows.append(
                observation(
                    "resolv_conf_present",
                    bool(resolv.strip()),
                    source="network_diagnostics.linux",
                )
            )
        except OSError:
            rows.append(
                observation(
                    "resolv_conf_present",
                    False,
                    source="network_diagnostics.linux",
                    limitations=["resolv_conf_unavailable"],
                )
            )
        rows.extend(listening_port_observations(source="network_diagnostics.linux"))
        return rows

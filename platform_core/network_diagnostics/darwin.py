"""macOS read-only network diagnostics — PARTIAL foundation (no WinINET/WinHTTP)."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from platform_core.network_diagnostics.base import (
    NetworkDiagnosticsProvider,
    dns_observation,
    observation,
)
from platform_core.network_diagnostics.listeners import listening_port_observations

_ENV_KEYS = (
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
    "all_proxy",
    "ALL_PROXY",
)


def _run_networksetup(args: list[str], *, timeout: float = 8.0) -> tuple[int, str]:
    if shutil.which("networksetup") is None:
        return 127, ""
    try:
        proc = subprocess.run(
            ["networksetup", *args],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return 1, ""


def _list_network_services() -> list[str]:
    code, out = _run_networksetup(["-listallnetworkservices"])
    if code != 0:
        return []
    services: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("An asterisk"):
            continue
        services.append(line)
    return services


def _parse_proxy_line_block(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        out[key.strip().lower().replace(" ", "_")] = val.strip()
    return out


def collect_networksetup_proxy_hints() -> list[dict[str, Any]]:
    """Read-only ``networksetup`` proxy hints for the first available network service."""
    rows: list[dict[str, Any]] = []
    lim = [
        "networksetup_hints_are_not_wininet_winhttp_parity",
        "proxy_enable_from_networksetup_is_candidate_evidence_not_proof",
    ]
    if shutil.which("networksetup") is None:
        rows.append(
            observation(
                "networksetup_available",
                False,
                source="network_diagnostics.darwin",
                limitations=lim + ["networksetup_not_on_path"],
            )
        )
        return rows

    rows.append(
        observation(
            "networksetup_available",
            True,
            source="network_diagnostics.darwin",
            limitations=lim,
        )
    )
    services = _list_network_services()
    if not services:
        rows.append(
            observation(
                "networksetup_services_found",
                0,
                source="network_diagnostics.darwin",
                limitations=lim + ["networksetup_list_services_failed"],
            )
        )
        return rows

    service = services[0]
    rows.append(
        observation(
            "networksetup_primary_service",
            service,
            source="network_diagnostics.darwin",
            limitations=lim,
        )
    )
    for proxy_kind, signal in (
        ("webproxy", "networksetup_web_proxy"),
        ("securewebproxy", "networksetup_secure_web_proxy"),
    ):
        code, out = _run_networksetup([f"-get{proxy_kind}", service])
        if code != 0:
            rows.append(
                observation(
                    f"{signal}_error",
                    "probe_failed",
                    source="network_diagnostics.darwin",
                    limitations=lim,
                )
            )
            continue
        parsed = _parse_proxy_line_block(out)
        enabled = parsed.get("enabled", "").lower() == "yes"
        rows.append(
            observation(
                f"{signal}_enabled",
                enabled,
                source="network_diagnostics.darwin",
                limitations=lim,
            )
        )
        server = parsed.get("server", "")
        port = parsed.get("port", "")
        if enabled and (server or port):
            rows.append(
                observation(
                    f"{signal}_endpoint",
                    f"{server}:{port}".strip(":"),
                    source="network_diagnostics.darwin",
                    limitations=lim,
                )
            )
    return rows


class DarwinNetworkDiagnostics(NetworkDiagnosticsProvider):
    """Observe-only macOS diagnostics — env proxy, networksetup hints, listening ports."""

    def os_family(self) -> str:
        """Provide os family behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return "darwin"

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
        return [
            "macOS path is observe-only PARTIAL support — no WinINET/WinHTTP/registry collectors.",
            "networksetup and env proxy hints are candidate evidence, not malware or MITM proof.",
            "Listening-port summary does not attribute processes on macOS foundation path.",
        ]

    def collect_observations(self) -> list[dict[str, Any]]:
        """Collect observations for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May read local system, file, or network state through configured providers.
        """
        import socket

        rows: list[dict[str, Any]] = [
            observation("os_family", "darwin", source="network_diagnostics.darwin"),
            observation("hostname", socket.gethostname(), source="network_diagnostics.darwin"),
            dns_observation(),
        ]
        for key in _ENV_KEYS:
            val = os.environ.get(key)
            if val:
                rows.append(
                    observation(
                        f"env_{key.lower()}",
                        val,
                        source="network_diagnostics.darwin",
                        limitations=["env_proxy_is_candidate_evidence_not_proof"],
                    )
                )
        rows.extend(collect_networksetup_proxy_hints())
        rows.extend(listening_port_observations(source="network_diagnostics.darwin"))
        return rows

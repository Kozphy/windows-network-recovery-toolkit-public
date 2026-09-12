"""Windows read-only network diagnostics (WinINET/WinHTTP observation tiers)."""

from __future__ import annotations

import os
import socket
from typing import Any

from platform_core.network_diagnostics.base import (
    NetworkDiagnosticsProvider,
    dns_observation,
    observation,
)


class WindowsNetworkDiagnostics(NetworkDiagnosticsProvider):
    """Windows host diagnostics; remediation remains policy-gated elsewhere."""

    def os_family(self) -> str:
        """Provide os family behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return "windows"

    def live_remediation_supported(self) -> bool:
        """Provide live remediation supported behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return True

    def limitations(self) -> list[str]:
        """Provide limitations behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return [
            "WinINET/WinHTTP reads are observations, not proof of registry writer identity.",
            "Policy ALLOW on preview does not imply safe autonomous repair.",
        ]

    def collect_observations(self) -> list[dict[str, Any]]:
        """Collect observations for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May read local system, file, or network state through configured providers.
        """
        rows: list[dict[str, Any]] = [
            observation("os_family", "windows", source="network_diagnostics.windows"),
            observation("hostname", socket.gethostname(), source="network_diagnostics.windows"),
            dns_observation(),
        ]
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy"):
            val = os.environ.get(key)
            if val:
                rows.append(
                    observation(f"env_{key.lower()}", val, source="network_diagnostics.windows")
                )
        rows.extend(self._win_proxy_observations())
        return rows

    def _win_proxy_observations(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            from platform_core.product_contract import (
                probe_localhost_listener,
                probe_winhttp_proxy,
                probe_wininet_proxy,
            )

            wininet = probe_wininet_proxy()
            observed = wininet.observed_value if isinstance(wininet.observed_value, dict) else {}
            if observed:
                if "proxy_enable" in observed:
                    out.append(
                        observation(
                            "proxy_enable",
                            observed.get("proxy_enable"),
                            source=wininet.source,
                            status=wininet.status,
                            evidence_level="observation",
                        )
                    )
                if observed.get("proxy_server"):
                    out.append(
                        observation(
                            "proxy_server",
                            observed.get("proxy_server"),
                            source=wininet.source,
                            evidence_level="observation",
                        )
                    )
            winhttp = probe_winhttp_proxy()
            out.append(
                observation(
                    "winhttp_proxy_state",
                    winhttp.observed_value
                    if isinstance(winhttp.observed_value, str)
                    else str(winhttp.observed_value)[:500],
                    source=winhttp.source,
                    status=winhttp.status,
                    evidence_level="observation",
                )
            )
            listener = probe_localhost_listener(wininet)
            listener_val = listener.observed_value
            if isinstance(listener_val, dict):
                out.append(
                    observation(
                        "localhost_listener_port_open",
                        listener_val.get("port_open"),
                        source=listener.source,
                        status=listener.status,
                        evidence_level="observation",
                        limitations=["listener_correlation_not_causation"],
                    )
                )
            else:
                out.append(
                    observation(
                        "localhost_listener_hint",
                        listener_val,
                        source=listener.source,
                        status=listener.status,
                        evidence_level="observation",
                        limitations=["listener_correlation_not_causation"],
                    )
                )
        except Exception as exc:  # noqa: BLE001 — diagnostics must not crash API
            out.append(
                observation(
                    "windows_proxy_probe_error",
                    str(exc)[:500],
                    source="network_diagnostics.windows",
                    limitations=["collector_import_failed"],
                )
            )
        return out

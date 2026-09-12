"""Fallback read-only diagnostics for macOS and unknown hosts."""

from __future__ import annotations

import socket
from typing import Any

from platform_core.network_diagnostics.base import (
    NetworkDiagnosticsProvider,
    detect_os_family,
    dns_observation,
    observation,
)


class GenericNetworkDiagnostics(NetworkDiagnosticsProvider):
    """Minimal cross-platform observations when no OS-specific provider exists."""

    def os_family(self) -> str:
        """Provide os family behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return detect_os_family()

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
            "Generic observe-only provider; no OS-specific proxy/registry collectors wired.",
            "Observation != proof; correlation != causation.",
        ]

    def collect_observations(self) -> list[dict[str, Any]]:
        """Collect observations for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May read local system, file, or network state through configured providers.
        """
        return [
            observation("os_family", detect_os_family(), source="network_diagnostics.generic"),
            observation("hostname", socket.gethostname(), source="network_diagnostics.generic"),
            dns_observation(),
        ]

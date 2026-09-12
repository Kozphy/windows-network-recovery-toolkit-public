"""Windows endpoint evidence collector — FULL platform support."""

from __future__ import annotations

from typing import Any

from platform_core.network_diagnostics.windows import WindowsNetworkDiagnostics
from src.platform_core.evidence_collection.base import EndpointEvidenceCollector
from src.platform_core.evidence_collection.models import OsFamily, PlatformSupportLevel


class WindowsEndpointEvidenceCollector(EndpointEvidenceCollector):
    """Delegates to existing Windows network diagnostics — WinINET/WinHTTP observation tier."""

    def __init__(self, provider: WindowsNetworkDiagnostics | None = None) -> None:
        """Initialize the windows endpoint evidence collector instance.

        Args:
            provider: provider supplied by the caller.

        Returns:
            None.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        self._provider = provider or WindowsNetworkDiagnostics()

    @property
    def collector_id(self) -> str:
        """Return collector id.

        Returns:
            The computed `str` value.

        Side effects:
            Collects observations from the configured evidence source.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return "windows_network_diagnostics_v1"

    def os_family(self) -> OsFamily:
        """Return os family.

        Returns:
            The computed `OsFamily` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return "windows"

    def platform_support_level(self) -> PlatformSupportLevel:
        """Return platform support level.

        Returns:
            The computed `PlatformSupportLevel` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return "FULL"

    def limitations(self) -> list[str]:
        """Return limitations.

        Returns:
            The computed `list[str]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return list(self._provider.limitations())

    def live_remediation_supported(self) -> bool:
        """Return live remediation supported.

        Returns:
            The computed `bool` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return bool(self._provider.live_remediation_supported())

    def collect_observations(self) -> list[dict[str, Any]]:
        """Collect observations.

        Returns:
            The computed `list[dict[str, Any]]` value.

        Side effects:
            Collects observations from the configured evidence source.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return list(self._provider.collect_observations())

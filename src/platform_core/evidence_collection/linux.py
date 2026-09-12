"""Linux endpoint evidence collector — PARTIAL platform support (foundation)."""

from __future__ import annotations

from typing import Any

from platform_core.network_diagnostics.linux import LinuxNetworkDiagnostics
from src.platform_core.evidence_collection.base import EndpointEvidenceCollector
from src.platform_core.evidence_collection.models import OsFamily, PlatformSupportLevel

_LINUX_FOUNDATION_LIMITATIONS = [
    "Linux evidence path is PARTIAL foundation — not WinINET/WinHTTP/registry parity.",
    "Environment proxy variables, gsettings hints, and listener summary are candidate evidence only.",
    "Listening-port summary does not attribute processes on Linux foundation path.",
    "Live registry-style remediation is not supported on Linux agents.",
    "Classification on Linux must include limitations[] — observation is not proof.",
]


class LinuxEndpointEvidenceCollector(EndpointEvidenceCollector):
    """Observe-only Linux collector — delegates to network_diagnostics.linux."""

    def __init__(self, provider: LinuxNetworkDiagnostics | None = None) -> None:
        """Initialize the linux endpoint evidence collector instance.

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
        self._provider = provider or LinuxNetworkDiagnostics()

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
        return "linux_network_diagnostics_v1"

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
        return "linux"

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
        return "PARTIAL"

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
        merged = list(_LINUX_FOUNDATION_LIMITATIONS)
        merged.extend(self._provider.limitations())
        return merged

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
        return False

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

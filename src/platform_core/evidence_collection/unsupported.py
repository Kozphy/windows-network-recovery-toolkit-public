"""Explicit NOT_SUPPORTED collector for unknown host platforms."""

from __future__ import annotations

from typing import Any

from src.platform_core.evidence_collection.base import EndpointEvidenceCollector
from src.platform_core.evidence_collection.models import OsFamily, PlatformSupportLevel

_UNSUPPORTED_LIMITATIONS = [
    "Platform is NOT_SUPPORTED for endpoint evidence collection in this toolkit version.",
    "No OS-specific proxy or registry collectors are available for this host class.",
    "Do not infer reliability incidents from empty observation sets.",
    "Observation is not proof; correlation is not causation.",
]


class UnsupportedPlatformEvidenceCollector(EndpointEvidenceCollector):
    """Returns an empty observation set with explicit NOT_SUPPORTED labeling."""

    def __init__(self, os_family: OsFamily = "unknown") -> None:
        """Initialize the unsupported platform evidence collector instance.

        Args:
            os_family: os family supplied by the caller.

        Returns:
            None.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        self._os_family = os_family

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
        return "unsupported_platform_v1"

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
        return self._os_family

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
        return "NOT_SUPPORTED"

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
        return list(_UNSUPPORTED_LIMITATIONS)

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
        return []

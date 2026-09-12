"""Factory for OS-specific read-only endpoint evidence collectors."""

from __future__ import annotations

from typing import Any

from platform_core.network_diagnostics.base import detect_os_family
from src.platform_core.evidence_collection.base import EndpointEvidenceCollector
from src.platform_core.evidence_collection.darwin import DarwinEndpointEvidenceCollector
from src.platform_core.evidence_collection.linux import LinuxEndpointEvidenceCollector
from src.platform_core.evidence_collection.models import EndpointEvidenceBundle, OsFamily
from src.platform_core.evidence_collection.unsupported import UnsupportedPlatformEvidenceCollector
from src.platform_core.evidence_collection.windows import WindowsEndpointEvidenceCollector


def get_endpoint_evidence_collector(
    os_family: OsFamily | None = None,
) -> EndpointEvidenceCollector:
    """Return the evidence collector for ``os_family`` or the current host.

    Args:
        os_family: Optional override for tests and fixture routing. When ``None``,
            uses :func:`platform_core.network_diagnostics.base.detect_os_family`.

    Returns:
        An :class:`EndpointEvidenceCollector` instance. Unknown families receive
        :class:`UnsupportedPlatformEvidenceCollector` (NOT_SUPPORTED).
    """
    family: OsFamily = os_family or detect_os_family()  # type: ignore[assignment]
    if family == "windows":
        return WindowsEndpointEvidenceCollector()
    if family == "linux":
        return LinuxEndpointEvidenceCollector()
    if family == "darwin":
        return DarwinEndpointEvidenceCollector()
    return UnsupportedPlatformEvidenceCollector(os_family=family)


def collect_endpoint_evidence(os_family: OsFamily | None = None) -> dict[str, Any]:
    """Collect one read-only evidence bundle and return a JSON-serializable dict."""
    bundle: EndpointEvidenceBundle = get_endpoint_evidence_collector(os_family).collect_bundle()
    return bundle.to_dict()

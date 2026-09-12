"""Base contract for OS-specific endpoint evidence collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.platform_core.evidence_collection.models import (
    EndpointEvidenceBundle,
    OsFamily,
    PlatformSupportLevel,
)


class EndpointEvidenceCollector(ABC):
    """Read-only endpoint evidence collector contract.

    Implementations must not mutate host state, spawn remediation subprocesses,
    or claim malware/compromise detection.
    """

    @property
    @abstractmethod
    def collector_id(self) -> str:
        """Stable identifier written to spool rows and audit metadata."""

    @abstractmethod
    def os_family(self) -> OsFamily:
        """OS family this collector targets."""

    @abstractmethod
    def platform_support_level(self) -> PlatformSupportLevel:
        """Honest support label — do not return FULL for non-Windows proxy registry paths."""

    @abstractmethod
    def limitations(self) -> list[str]:
        """Platform and epistemic limitations for classifications using this evidence."""

    @abstractmethod
    def live_remediation_supported(self) -> bool:
        """Whether policy-gated remediation exists for this OS in the toolkit today."""

    @abstractmethod
    def collect_observations(self) -> list[dict[str, object]]:
        """Return normalized observation dicts (read-only probes only)."""

    def collect_bundle(self) -> EndpointEvidenceBundle:
        """Build a complete evidence bundle for one collection cycle."""
        lim = list(self.limitations())
        level = self.platform_support_level()
        if level in ("PARTIAL", "NOT_SUPPORTED") and not lim:
            lim.append("platform_support_limited_explicit_limitations_required")
        return EndpointEvidenceBundle(
            os_family=self.os_family(),
            platform_support_level=level,
            collector_id=self.collector_id,
            observations=[dict(row) for row in self.collect_observations()],
            limitations=lim,
            live_remediation_supported=self.live_remediation_supported(),
        )

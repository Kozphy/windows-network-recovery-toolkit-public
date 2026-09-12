"""Models for endpoint evidence collection bundles."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

PlatformSupportLevel = Literal["FULL", "PARTIAL", "NOT_SUPPORTED"]
OsFamily = Literal["windows", "linux", "darwin", "unknown"]


@dataclass(frozen=True)
class EndpointEvidenceBundle:
    """Normalized read-only evidence payload for one collection cycle.

    Attributes:
        os_family: Detected or forced host OS family.
        platform_support_level: Honest capability label for this host class.
        collector_id: Stable identifier for the collector implementation.
        observations: Normalized observation dicts (signal_name, value, source, ...).
        limitations: Epistemic and platform boundaries — must not be empty on PARTIAL/NOT_SUPPORTED.
        live_remediation_supported: Whether policy-gated live remediation exists for this OS (Windows only).
        collected_at_utc: ISO-8601 UTC timestamp for audit correlation.
    """

    os_family: OsFamily
    platform_support_level: PlatformSupportLevel
    collector_id: str
    observations: list[dict[str, Any]]
    limitations: list[str]
    live_remediation_supported: bool
    collected_at_utc: str = field(
        default_factory=lambda: datetime.now(UTC).replace(microsecond=0).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping for spool files and APIs."""
        return {
            "os_family": self.os_family,
            "platform_support_level": self.platform_support_level,
            "collector_id": self.collector_id,
            "observations": self.observations,
            "limitations": list(self.limitations),
            "live_remediation_supported": self.live_remediation_supported,
            "collected_at_utc": self.collected_at_utc,
            "epistemic_note": (
                "Observations are candidate signals only. "
                "Classification is not accusation. Policy ALLOW is not a safety guarantee."
            ),
        }

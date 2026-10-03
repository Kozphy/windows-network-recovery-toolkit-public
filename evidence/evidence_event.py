"""Normalized evidence record for ingestion prior to attribution correlation.

Evidence may contain endpoint/network identifiers while it remains local. Any
record crossing a publication boundary (reports, CI artifacts, GitHub, support
bundles) should use :meth:`EvidenceEvent.as_sanitized_dict`.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from evidence.redaction import sanitize_evidence

EvidenceSubtype = Literal[
    "procmon_csv", "sysmon_eid13", "etw_stub", "registry_poll", "listener_hint", "other"
]


@dataclass
class EvidenceEvent:
    """Single correlated evidence datum prior to fused attribution."""

    event_id: str
    timestamp_utc: str
    endpoint_id: str
    schema_version: str = "1"
    evidence_type: EvidenceSubtype | str = "other"
    payload: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the raw local record.

        Do not use this representation for public reports or CI artifacts when
        payloads may contain identifying network data.
        """

        return asdict(self)

    def as_sanitized_dict(self, *, salt: str = "wnrt-public-evidence-v1") -> dict[str, Any]:
        """Serialize with deterministic IP/MAC/host identifier redaction."""

        return sanitize_evidence(asdict(self), salt=salt)

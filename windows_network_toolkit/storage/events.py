"""Normalized evidence events for the local monitoring dashboard.

Module responsibility:
    Define the ``EvidenceEvent`` schema, UTC timestamp helpers, and shared epistemic
    ``DEFAULT_LIMITATIONS`` strings used by watchers and Procmon import.

System placement:
    Consumed by ``EvidenceEventStore``, ``ProxyWatcher``, and ``procmon_import``.

Key invariants:
    * ``data`` holds observations; ``classification`` / ``proof_tier`` / ``confidence`` hold
      inferences and must not be treated as registry-writer proof.
    * Timestamps are UTC ISO-8601 (``datetime.now(UTC).isoformat()``).

Data shape:
    See ``EvidenceEvent.to_dict`` — JSONL lines match that dict exactly.

Missing / malformed data:
    ``from_dict`` fills missing ids/timestamps/sources with safe defaults rather than raising.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def new_event_id() -> str:
    """Allocate a short unique event id (``ev-`` + 12 hex chars)."""

    return f"ev-{uuid.uuid4().hex[:12]}"


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with offset."""

    return datetime.now(UTC).isoformat()


@dataclass
class EvidenceEvent:
    """Normalized evidence event — observations in ``data``, inferences in classification fields.

    Attributes:
        event_id: Stable id for UI row keys and clear-filter tracking.
        timestamp: UTC ISO-8601 when the event was created or imported.
        source: Emitter id (e.g. ``proxy_watcher``, ``procmon_csv``).
        event_type: Machine-oriented type (e.g. ``proxy_state_change``).
        severity: ``info`` | ``warning`` | ``error`` (UI filter).
        summary: One-line operator-facing description.
        data: Observation payload (old/new state, listener, process name, etc.).
        incident_id: Optional grouping id for related rows.
        classification: Optional primary classification code from the existing engine.
        proof_tier: Optional governance proof tier string.
        confidence: Optional ordinal confidence float from classification (not probability).
        limitations: Epistemic caveats that must travel with the event.
    """

    event_id: str
    timestamp: str
    source: str
    event_type: str
    severity: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    incident_id: str | None = None
    classification: str | None = None
    proof_tier: str | None = None
    confidence: float | None = None
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict for JSONL persistence and CLI output."""

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "summary": self.summary,
            "data": dict(self.data),
            "incident_id": self.incident_id,
            "classification": self.classification,
            "proof_tier": self.proof_tier,
            "confidence": self.confidence,
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> EvidenceEvent:
        """Rehydrate an event from JSON/JSONL; tolerate missing optional fields.

        Args:
            raw: Mapping from ``to_dict`` or external import. Missing required-ish fields
                are defaulted (new id, now timestamp, ``unknown`` source).

        Returns:
            ``EvidenceEvent`` instance.
        """

        return cls(
            event_id=str(raw.get("event_id") or new_event_id()),
            timestamp=str(raw.get("timestamp") or utc_now_iso()),
            source=str(raw.get("source") or "unknown"),
            event_type=str(raw.get("event_type") or "unknown"),
            severity=str(raw.get("severity") or "info"),
            summary=str(raw.get("summary") or ""),
            data=dict(raw.get("data") or {}),
            incident_id=raw.get("incident_id"),
            classification=raw.get("classification"),
            proof_tier=raw.get("proof_tier"),
            confidence=float(raw["confidence"]) if raw.get("confidence") is not None else None,
            limitations=list(raw.get("limitations") or []),
        )


DEFAULT_LIMITATIONS = [
    "Observation is not proof.",
    "Correlation is not causation.",
    "A directly observed process operation does not prove human intent.",
    "Listener presence is correlation with ProxyServer — not registry-writer proof.",
]

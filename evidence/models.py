"""Shared attribution data shapes (stdlib ``dataclass`` — no filesystem or sockets).

Module responsibility:
    Defines portable records returned by :func:`~evidence.attribution_engine.build_attribution`
    before optional persistence to ``platform_data/attribution_records.jsonl``.

Schema notes:
    * ``AttributionLevel`` strings are enumerated by Literal type—serializers persist them verbatim.
    * ``confidence`` is a unitless float in ``[0, 1]`` produced by scorer clamping callers must not reinterpret as statistical p-values.
    * ``EvidenceItem.source`` identifies the pipeline stage (“registry_poll”, “sysmon”, …); treat as categorical, not localized UI text.

Timezone:
    Timestamps are **not** embedded here—callers stamping rows should use RFC3339 UTC per
    ``platform_core.models.utc_now_iso`` conventions when persisting payloads.

Malformed input handling:
    :meth:`AttributionResult.as_dict` ignores validation beyond JSON-serializable leaves; malformed
    upstream dicts fail before instantiation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

AttributionLevel = Literal[
    "unknown",
    "heuristic",
    "listener_match",
    "procmon_confirmed",
    "sysmon_confirmed",
    "etw_confirmed",
]


def attribution_level_aliases() -> dict[str, AttributionLevel]:
    """Map deprecated serialized labels onto canonical :data:`AttributionLevel` literals."""

    return {
        "evidence_supported": "procmon_confirmed",
        "confirmed_by_eventlog": "sysmon_confirmed",
    }


def coerce_attribution_level(raw: str) -> AttributionLevel:
    """Provide coerce attribution level behavior for toolkit workflows.

    Args:
        raw: Value supplied by the caller for raw.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    aliases = attribution_level_aliases()
    if raw in aliases:
        return aliases[raw]
    if raw in (
        "unknown",
        "heuristic",
        "listener_match",
        "procmon_confirmed",
        "sysmon_confirmed",
        "etw_confirmed",
    ):
        return raw  # type: ignore[return-value]
    return "unknown"


@dataclass(frozen=True)
class EvidenceItem:
    """One normalized observation feeding the scorer.

    Attributes:
        source: Pipeline facet label (registry_poll | listener_match | proc_inventory |
            parent_process | sysmon | procmon | etw).
        detail: Compact human-readable string—already sanitized by upstream producers when possible.
        weight_hint: Advisory weight used only inside :mod:`evidence.attribution_engine`; not a calibrated probability contribution.
    """

    source: str
    detail: str
    weight_hint: float = 0.0


@dataclass
class AttributionResult:
    """Fused attribution output for correlation with ``FailureEvent.event_id``.

    Attributes:
        event_id: Mirrors platform failure ingestion identifier.
        candidate_actor: Executable name/path fragment—**hypothesis**, not adjudicated malware verdict.
        confidence: Float ``0…1`` clamped scorer output.
        attribution_level: Discrete ladder (unknown → heuristic → listener_match → procmon/sysmon/etw confirmed).
        evidence: Ordered items explaining score components.
        notes: Free-text caveats—including honest-boundary disclaimers—safe for auditors.
    """

    event_id: str
    candidate_actor: str
    confidence: float
    attribution_level: AttributionLevel
    evidence: list[EvidenceItem] = field(default_factory=list)
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Serialize-to-JSON-friendly mapping for API sinks and pytest fixtures.

        Returns:
            ``dict`` with rounded ``confidence``, evidence list coerced into plain dict rows.

        Side effects:
            Allocates—does not mutate ``self``.
        """

        return {
            "event_id": self.event_id,
            "candidate_actor": self.candidate_actor,
            "confidence": round(self.confidence, 6),
            "attribution_level": self.attribution_level,
            "evidence": [
                {"source": e.source, "detail": e.detail, "weight_hint": e.weight_hint}
                for e in self.evidence
            ],
            "notes": self.notes,
        }

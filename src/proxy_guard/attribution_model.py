"""Typed payloads for layered WinINET proxy registry attribution (live + CSV-shaped inputs).

Module responsibility:
    Holds dataclasses for **pipeline JSON** layered attribution—Sysmon-derived rows, Procmon imports,
    listener alignment, polling heuristics—without implementing scoring (see
    :mod:`src.proxy_guard.attribution_engine`).

System placement:
    Imported by proxy-guard attribution paths alongside :mod:`src.proxy_guard.sysmon_attribution`.
    Distinct from :class:`~src.proxy_guard.models.AttributionResult`, which feeds **policy**
    evaluation; layered outputs may be transformed via ``layered_to_heuristic_pipeline``.

Key invariants:
    * ``AttributionEvidence.source`` labels are categorical provenance hints—localized UI text must map
      from these codes, not treat them as phrases.
    * ``confidence_score`` is author-assigned heuristic weight (often ``0.0…1.0``) for ranking, not a
      calibrated Bayesian probability unless a producer documents otherwise.

Data shape / validation:
    Optional fields intentionally allow ``None``; serializers use :meth:`~ProxyActor.to_jsonable` and
    cousins to omit null leaves. ``raw_excerpt`` should avoid secrets—callers redact before persistence.

Timezone:
    ``ProxyActor.started_at`` and ``AttributionEvidence.observed_at`` are opaque strings when set;
    Sysmon-derived rows typically use exporter-local timestamps—normalize at persistence boundaries.

How other modules use it:
    ``collect_sysmon_proxy_events`` appends :class:`AttributionEvidence`; merge layers downstream into
    :class:`LayeredAttributionResult`.

Failure modes:
    Malformed upstream dicts surface before instantiation; layering code must tolerate empty evidence lists.

See Also:
    ``docs/proxy_guard_attribution.md`` for honesty boundaries versus ``proxy-watch`` logs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

AttributionConfidenceLabel = Literal["high", "medium", "low", "unknown"]

AttributionEvidenceSource = Literal[
    "sysmon_event_13",
    "procmon_csv",
    "localhost_listener",
    "process_inventory_heuristic",
    "registry_polling",
    "unknown",
]


@dataclass
class ProxyActor:
    """Hypothetical Windows process identity attached to attribution evidence."""

    pid: int | None = None
    process_name: str | None = None
    image_path: str | None = None
    command_line: str | None = None
    user: str | None = None
    parent_pid: int | None = None
    parent_process_name: str | None = None
    signer: str | None = None
    started_at: str | None = None

    def to_jsonable(self) -> dict[str, Any]:
        """Return a shallow JSON-ready dict omitting unset fields.

        Returns:
            Key/value pairs for pipeline consumers—no schema versioning embedded here.

        Side effects:
            Allocates dict only.
        """

        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class AttributionEvidence:
    """Single observation correlated with proxy registry changes."""

    source: AttributionEvidenceSource | str
    observed_at: str | None = None
    event_id: str | None = None
    target_key: str | None = None
    target_value_name: str | None = None
    old_value: str | None = None
    new_value: str | None = None
    raw_excerpt: dict[str, Any] | None = None
    confidence_score: float = 0.0
    notes: list[str] = field(default_factory=list)

    def to_jsonable(self) -> dict[str, Any]:
        """Serialize evidence for JSON logs and dashboards.

        Returns:
            Stable key set including copied ``notes`` list (decoupled from dataclass mutate sharing).

        Side effects:
            None beyond allocation.
        """

        return {
            "source": self.source,
            "observed_at": self.observed_at,
            "event_id": self.event_id,
            "target_key": self.target_key,
            "target_value_name": self.target_value_name,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "raw_excerpt": self.raw_excerpt,
            "confidence_score": self.confidence_score,
            "notes": list(self.notes),
        }


@dataclass
class LayeredAttributionResult:
    """Fused attribution after ordered evidence sources produce a ranked actor hypothesis."""

    candidate_actor: ProxyActor | None
    attribution_confidence: AttributionConfidenceLabel
    attribution_method: str
    evidence: list[AttributionEvidence] = field(default_factory=list)
    attribution_notes: list[str] = field(default_factory=list)

    def to_jsonable(self) -> dict[str, Any]:
        """Export nested evidence rows for pipelines and previews.

        Returns:
            Dict with camelCase-free snake keys matching internal field semantics.

        Side effects:
            None.
        """

        ca = None if self.candidate_actor is None else self.candidate_actor.to_jsonable()
        return {
            "candidate_actor": ca,
            "attribution_confidence": self.attribution_confidence,
            "attribution_method": self.attribution_method,
            "evidence": [e.to_jsonable() for e in self.evidence],
            "attribution_notes": list(self.attribution_notes),
        }

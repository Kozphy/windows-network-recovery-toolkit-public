"""Merge collector and fixture signals into a chronological evidence timeline.

Module responsibility:
    Provide ``TimelineBuilder``, the primary assembly point for evidence
    timelines.  Accepts raw signals, collector payloads, legacy proxy timeline
    objects, and JSONL files; merges them into a single deduplicated,
    chronologically sorted ``EvidenceBundle``.

System placement:
    Invoked by the pipeline (``windows_network_toolkit.pipeline``) and by
    replay/audit utilities.  Upstream of the ``decision`` layer; downstream of
    individual collectors and converters.

Key invariants:
    * Deduplication is keyed on ``(timestamp, signal, observed_value)`` — the
      same observation from two sources is collapsed to one event.
    * Events are sorted by the ``timestamp`` string (ISO-8601 lexicographic
      order); callers must supply well-formed timestamps for correct ordering.
    * ``build()`` is idempotent given the same accumulated events; it does not
      mutate the internal event list.

Side effects:
    ``ingest_jsonl`` reads from disk (``Path.read_text``).  All other methods
    are in-memory and free of I/O.

Failure modes:
    ``ingest_jsonl`` raises ``FileNotFoundError`` / ``json.JSONDecodeError``
    for missing or malformed files.  ``build()`` never raises unless
    ``utc_now_iso()`` (platform_core) fails.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from platform_core.models import utc_now_iso

from .converters import from_proxy_timeline_event, from_signal_dict
from .evidence_model import EvidenceBundle, EvidenceEvent


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class TimelineBuilder:
    """Assemble deduplicated, chronological evidence timelines.

    Collects events from multiple heterogeneous sources (signal dicts,
    collector payloads, JSONL files, proxy timeline objects) and produces a
    single ``EvidenceBundle`` via ``build()``.

    The builder is append-only during accumulation; ``build()`` performs
    sorting and deduplication at snapshot time without modifying internal state.

    Example::

        builder = TimelineBuilder(incident_id="inc-001")
        builder.add_signal("PROXY_ENABLE", "1", source="registry")
        builder.ingest_jsonl(Path("evidence.jsonl"))
        bundle = builder.build(summary="Proxy drift detected")
    """

    def __init__(self, *, incident_id: str | None = None, host_id: str = "local") -> None:
        """Initialise a new ``TimelineBuilder``.

        Args:
            incident_id: Optional incident identifier; a random ID is generated
                when omitted.
            host_id: Endpoint identifier; defaults to ``"local"`` for single-
                host analysis.
        """
        self.incident_id = incident_id or f"incident-{uuid.uuid4().hex[:12]}"
        self.host_id = host_id
        self._events: list[EvidenceEvent] = []

    def add_signal(
        self, name: str, value: Any, *, timestamp: str | None = None, source: str = "signal"
    ) -> None:
        """Append a single named signal observation.

        Args:
            name: Signal name (e.g. ``"PROXY_ENABLE"``).
            value: Observed value; converted to string for storage.
            timestamp: ISO-8601 UTC timestamp; defaults to ``utcnow`` when
                omitted.
            source: Provenance label for the event.
        """
        self._events.append(
            from_signal_dict(name, value, timestamp=timestamp or _now_iso(), source=source)
        )

    def add_event(self, event: EvidenceEvent) -> None:
        """Append a pre-built ``EvidenceEvent`` directly.

        Args:
            event: A fully populated ``EvidenceEvent`` instance; stored without
                modification.
        """
        self._events.append(event)

    def ingest_collector_payload(self, payload: dict[str, Any], *, prefix: str = "") -> None:
        """Expand a flat collector dict into one signal event per key.

        The ``timestamp`` and ``source`` keys are consumed as metadata and not
        emitted as individual signals.

        Args:
            payload: Flat key-value dict from a collector run.
            prefix: Optional string prepended to each signal name (uppercased).
        """
        ts = str(payload.get("timestamp") or _now_iso())
        for key, value in payload.items():
            if key in {"timestamp", "source"}:
                continue
            signal = f"{prefix}{key}".upper() if prefix else key.upper()
            self.add_signal(
                signal, value, timestamp=ts, source=str(payload.get("source") or "collector")
            )

    def ingest_jsonl(self, path: Path | str) -> None:
        """Ingest evidence from a JSONL file, one event per line.

        Supports three row shapes:

        * ``{"signal": ..., "observed_value": ..., "timestamp": ...}``
        * ``{"name": ..., "value": ..., "timestamp": ...}``
        * Any other flat dict — delegated to ``ingest_collector_payload``.

        Args:
            path: Path to the JSONL file.

        Raises:
            FileNotFoundError: File does not exist.
            json.JSONDecodeError: A line is not valid JSON.
        """
        p = Path(path)
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                continue
            ts = str(row.get("timestamp") or row.get("timestamp_utc") or _now_iso())
            if "signal" in row:
                self.add_signal(
                    str(row["signal"]), row.get("observed_value", row.get("value")), timestamp=ts
                )
            elif "name" in row:
                self.add_signal(str(row["name"]), row.get("value"), timestamp=ts)
            else:
                self.ingest_collector_payload(row)

    def merge_proxy_timeline(self, events: list[Any]) -> None:
        """Convert and ingest a list of proxy timeline event objects.

        Each element is passed to ``from_proxy_timeline_event``; see that
        function for the supported duck-typed attribute set.

        Args:
            events: List of proxy timeline event objects (from
                ``proxy_reasoning`` scenario output).
        """
        for ev in events:
            self._events.append(from_proxy_timeline_event(ev))

    def build(self, *, summary: str = "", tags: list[str] | None = None) -> EvidenceBundle:
        """Produce a deduplicated, chronologically sorted ``EvidenceBundle``.

        Deduplication is keyed on ``(timestamp, signal, observed_value)``; the
        first occurrence wins.  Internal event list is not modified.

        Args:
            summary: Optional narrative summary attached to the bundle.
            tags: Optional classification or routing tags.

        Returns:
            A frozen ``EvidenceBundle`` snapshot of all accumulated events.
        """
        seen: set[tuple[str, str, str]] = set()
        deduped: list[EvidenceEvent] = []
        for ev in sorted(self._events, key=lambda e: e.timestamp):
            key = ev.dedupe_key()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(ev)
        return EvidenceBundle(
            incident_id=self.incident_id,
            created_at=utc_now_iso(),
            host_id=self.host_id,
            events=deduped,
            summary=summary,
            tags=tags or [],
        )

    def to_timeline_json(self, bundle: EvidenceBundle | None = None) -> list[dict[str, Any]]:
        """Return a condensed timeline JSON list, building the bundle if needed.

        Convenience wrapper around ``EvidenceBundle.to_timeline_json()``.

        Args:
            bundle: Pre-built bundle to render; if ``None``, ``build()`` is
                called implicitly using accumulated events.

        Returns:
            List of dicts with keys ``timestamp``, ``signal``,
            ``observed_value``, and ``severity``.
        """
        b = bundle or self.build()
        return b.to_timeline_json()

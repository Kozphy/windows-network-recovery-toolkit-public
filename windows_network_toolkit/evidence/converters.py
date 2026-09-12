"""Convert legacy and heterogeneous artefact shapes into typed EvidenceEvent rows.

Module responsibility:
    Adapter layer between raw collector payloads (dict blobs, proxy timeline
    objects, or plain signal key-value pairs) and the canonical
    ``EvidenceEvent`` model.  Normalises field names, assigns default
    categories, and generates stable UUIDs for events that lack IDs.

System placement:
    Called by ``TimelineBuilder`` (``timeline_builder.py``) and directly by
    tests that need to manufacture synthetic evidence events.  No business
    logic is applied here — severity heuristics are limited to known high-
    signal types (e.g. ``REGISTRY_VALUE_SET``).

Key invariants:
    * Original payload content is stored verbatim in ``raw_data`` — no
      field is discarded or overwritten without a fallback.
    * Severity escalation for ``REGISTRY_VALUE_SET`` and
      ``LOCALHOST_LISTENER_OBSERVED`` signals is the only interpretation
      added; all other fields reflect observed values only.
    * Observation ≠ proof; converters produce evidence records, not verdicts.

Side effects:
    None — all converters are pure functions; they do not write to disk,
    network, or registry.

Failure modes:
    Missing attributes on legacy objects are tolerated via ``getattr``
    fallbacks; malformed payloads may produce events with empty string
    fields rather than raising exceptions.
"""

from __future__ import annotations

import uuid
from typing import Any

from .evidence_model import EvidenceEvent


def from_collector_dict(
    payload: dict[str, Any],
    *,
    signal: str,
    category: str = "collector",
    source: str = "collector",
    timestamp: str,
) -> EvidenceEvent:
    """Convert a raw collector dict into an ``EvidenceEvent``.

    Args:
        payload: Arbitrary key-value dict from a collector run.  Must contain
            at least one key; an empty dict produces a valid but sparse event.
        signal: Canonical signal name to assign (caller-supplied; not inferred
            from the payload to avoid ambiguity).
        category: Event category tag; defaults to ``"collector"``.
        source: Source identifier; overridden by ``payload["source"]`` when
            present.
        timestamp: ISO-8601 UTC timestamp string (required by callers).

    Returns:
        A populated ``EvidenceEvent``.  ``raw_data`` holds a copy of the full
        original payload.
    """
    return EvidenceEvent(
        event_id=str(payload.get("event_id") or uuid.uuid4()),
        timestamp=timestamp,
        source=str(payload.get("source") or source),
        category=category,
        signal=signal,
        observed_value=str(payload),
        raw_data=dict(payload),
    )


def from_proxy_timeline_event(event: Any) -> EvidenceEvent:
    """Convert a proxy timeline event object into an ``EvidenceEvent``.

    Accepts any duck-typed object that carries the attributes produced by the
    proxy_reasoning timeline (``event_type``, ``timestamp_utc``, ``source``,
    ``title``, ``process_id``, ``confidence``, ``raw_reference``).  Missing
    attributes fall back to safe defaults rather than raising ``AttributeError``.

    Severity is elevated to ``"high"`` for ``REGISTRY_VALUE_SET`` and
    ``LOCALHOST_LISTENER_OBSERVED`` signals — both indicate potential proxy
    path manipulation.

    Args:
        event: Duck-typed proxy timeline event object.

    Returns:
        A normalised ``EvidenceEvent`` with ``category="timeline"``.
    """
    event_type = getattr(event, "event_type", None)
    signal = event_type.value if hasattr(event_type, "value") else str(event_type or "UNKNOWN")
    return EvidenceEvent(
        event_id=str(uuid.uuid4()),
        timestamp=str(getattr(event, "timestamp_utc", "") or ""),
        source=str(getattr(event, "source", "") or "timeline"),
        category="timeline",
        signal=signal,
        observed_value=str(getattr(event, "title", "") or ""),
        process_name="",
        pid=getattr(event, "process_id", None),
        confidence=float(getattr(event, "confidence", 0.0) or 0.0),
        severity="high"
        if signal in {"REGISTRY_VALUE_SET", "LOCALHOST_LISTENER_OBSERVED"}
        else "medium",
        raw_data=dict(getattr(event, "raw_reference", None) or {}),
    )


def from_signal_dict(
    name: str, value: Any, *, timestamp: str, source: str = "fixture"
) -> EvidenceEvent:
    """Wrap a bare signal name/value pair into an ``EvidenceEvent``.

    Primarily used by ``TimelineBuilder.add_signal`` and test fixtures that
    inject synthetic signals without a full collector payload.

    Args:
        name: Signal name (used as both ``signal`` and as the ``raw_data``
            ``"name"`` key).
        value: Observed value for the signal; stored as ``str`` in
            ``observed_value`` and verbatim in ``raw_data``.
        timestamp: ISO-8601 UTC timestamp string.
        source: Provenance label; defaults to ``"fixture"`` for test/replay
            contexts.

    Returns:
        A minimal ``EvidenceEvent`` with ``category="signal"``.
    """
    return EvidenceEvent(
        event_id=str(uuid.uuid4()),
        timestamp=timestamp,
        source=source,
        category="signal",
        signal=name,
        observed_value=str(value),
        raw_data={"name": name, "value": value},
    )

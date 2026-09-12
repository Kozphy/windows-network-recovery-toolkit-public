"""Append-only trisk domain event store."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from platform_core import storage
from src.platform_core.events.models import TriskDomainEvent, TriskEventType

CANONICAL_LOG = "trisk_domain_events.jsonl"


def _log_path(path: Path | None = None) -> Path:
    if path is not None:
        return path
    base = Path(os.getenv("PLATFORM_DATA_DIR", "platform_data"))
    return base / CANONICAL_LOG


class TriskEventStore:
    """JSONL event store with per-aggregate sequence."""

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the trisk event store instance.

        Args:
            path: path supplied by the caller.

        Returns:
            None.

        Side effects:
            May read or write local platform records depending on inputs.
        """
        self._path = _log_path(path)
        self._sequence_cache: dict[str, int] | None = None

    def _load_sequences(self) -> dict[str, int]:
        if self._sequence_cache is not None:
            return self._sequence_cache
        seq: dict[str, int] = {}
        for row in storage.iter_jsonl(self._path):
            if not isinstance(row, dict):
                continue
            agg = str(row.get("aggregate_id") or "")
            seq_num = int(row.get("sequence") or 0)
            if agg:
                seq[agg] = max(seq.get(agg, 0), seq_num)
        self._sequence_cache = seq
        return seq

    def next_sequence(self, aggregate_id: str) -> int:
        """Return next sequence.

        Args:
            aggregate_id: aggregate id supplied by the caller.

        Returns:
            The computed `int` value.

        Side effects:
            May read or write local platform records depending on inputs.
        """
        return self._load_sequences().get(aggregate_id, 0) + 1

    def append(self, event: TriskDomainEvent) -> TriskDomainEvent:
        """Append the requested value.

        Args:
            event: event supplied by the caller.

        Returns:
            The computed `TriskDomainEvent` value.

        Side effects:
            Appends data to the requested store.
        """
        storage.append_jsonl(self._path, event.model_dump(mode="json"))
        if self._sequence_cache is not None:
            self._sequence_cache[event.aggregate_id] = event.sequence
        self._mirror_db(event)
        return event

    def _mirror_db(self, event: TriskDomainEvent) -> None:
        try:
            from sqlmodel import Session

            from backend.db import get_engine, init_trisk_schema
            from backend.db.models import TriskDomainEventRow

            init_trisk_schema()
            with Session(get_engine()) as session:
                session.add(
                    TriskDomainEventRow(
                        event_id=event.event_id,
                        event_type=event.event_type.value,
                        aggregate_id=event.aggregate_id,
                        aggregate_type=event.aggregate_type,
                        sequence=event.sequence,
                        actor=event.actor,
                        correlation_id=event.correlation_id,
                        payload=dict(event.payload),
                        limitations=list(event.limitations),
                    )
                )
                session.commit()
        except Exception:
            pass

    def iter_events(
        self,
        *,
        aggregate_id: str | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> Iterator[TriskDomainEvent]:
        """Return iter events.

        Args:
            aggregate_id: aggregate id supplied by the caller.
            limit: limit supplied by the caller.
            offset: offset supplied by the caller.

        Returns:
            The computed `Iterator[TriskDomainEvent]` value.

        Side effects:
            May read or write local platform records depending on inputs.
        """
        rows: list[dict[str, Any]] = []
        for row in storage.iter_jsonl(self._path):
            if not isinstance(row, dict):
                continue
            if aggregate_id and row.get("aggregate_id") != aggregate_id:
                continue
            rows.append(row)
        for row in rows[offset : offset + limit]:
            yield TriskDomainEvent.model_validate(row)

    def list_events(
        self,
        *,
        aggregate_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[TriskDomainEvent]:
        """List events.

        Args:
            aggregate_id: aggregate id supplied by the caller.
            limit: limit supplied by the caller.
            offset: offset supplied by the caller.

        Returns:
            The computed `list[TriskDomainEvent]` value.

        Side effects:
            May read or write local platform records depending on inputs.
        """
        return list(self.iter_events(aggregate_id=aggregate_id, limit=limit, offset=offset))


_default_store: TriskEventStore | None = None


def get_event_store() -> TriskEventStore:
    """Get event store.

    Returns:
        The computed `TriskEventStore` value.

    Side effects:
        May read or write local platform records depending on inputs.
    """
    global _default_store
    if _default_store is None:
        _default_store = TriskEventStore()
    return _default_store


def reset_event_store() -> None:
    """Reset event store.

    Returns:
        None.

    Side effects:
        Updates process-local or test-scoped state.
    """
    global _default_store
    _default_store = None


def emit_trisk_event(
    event_type: TriskEventType,
    *,
    aggregate_id: str,
    aggregate_type: str = "evidence",
    actor: str = "system",
    correlation_id: str = "",
    payload: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
) -> TriskDomainEvent:
    """Return emit trisk event.

    Args:
        event_type: event type supplied by the caller.
        aggregate_id: aggregate id supplied by the caller.
        aggregate_type: aggregate type supplied by the caller.
        actor: actor supplied by the caller.
        correlation_id: correlation id supplied by the caller.
        payload: payload supplied by the caller.
        limitations: limitations supplied by the caller.

    Returns:
        The computed `TriskDomainEvent` value.

    Side effects:
        Records an event in the configured event store.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    store = get_event_store()
    event = TriskDomainEvent(
        event_type=event_type,
        aggregate_id=aggregate_id,
        aggregate_type=aggregate_type,  # type: ignore[arg-type]
        sequence=store.next_sequence(aggregate_id),
        actor=actor,
        correlation_id=correlation_id or aggregate_id,
        payload=payload or {},
        limitations=limitations or [],
    )
    store.append(event)
    try:
        from backend.trisk_metrics import inc

        inc("domain_events_appended_total", labels={"event_type": event_type.value})
    except Exception:
        pass
    return event

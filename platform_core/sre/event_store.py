"""Canonical append-only domain event store — single source of truth for SRE operations."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

from platform_core import storage

from .models import DomainEvent, DomainEventType, FailureDomainName

CANONICAL_LOG = "sre_domain_events.jsonl"


def _log_path(path: Path | None = None) -> Path:
    return path or storage.platform_data_dir() / CANONICAL_LOG


class DomainEventStore:
    """Append-only event store with per-aggregate sequence enforcement."""

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the DomainEventStore instance.

        Args:
            path: Value supplied by the caller for path.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
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
        """Provide next sequence behavior for toolkit workflows.

        Args:
            aggregate_id: Value supplied by the caller for aggregate id.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        seq = self._load_sequences()
        return seq.get(aggregate_id, 0) + 1

    def _event_exists(self, event_id: str) -> bool:
        for row in storage.iter_jsonl(self._path):
            if isinstance(row, dict) and row.get("event_id") == event_id:
                return True
        return False

    def append(self, event: DomainEvent, *, strict_sequence: bool = True) -> DomainEvent:
        """Append event; reject duplicate event_id or sequence gaps when strict."""
        if self._event_exists(event.event_id):
            raise ValueError(f"duplicate event_id: {event.event_id}")

        if strict_sequence:
            expected = self.next_sequence(event.aggregate_id)
            if event.sequence != expected:
                raise ValueError(
                    f"sequence mismatch for {event.aggregate_id}: "
                    f"expected {expected}, got {event.sequence}"
                )

        storage.append_jsonl(self._path, event.model_dump(mode="json"))
        if self._sequence_cache is not None:
            self._sequence_cache[event.aggregate_id] = event.sequence
        return event

    def iter_events(
        self,
        *,
        aggregate_id: str | None = None,
        correlation_id: str | None = None,
        limit: int = 10_000,
    ) -> Iterator[DomainEvent]:
        """Provide iter events behavior for toolkit workflows.

        Args:
            aggregate_id: Value supplied by the caller for aggregate id.
            correlation_id: Value supplied by the caller for correlation id.
            limit: Value supplied by the caller for limit.

        Yields:
            Observed values produced by the iterator.

        Side effects:
            None.
        """
        count = 0
        for row in storage.iter_jsonl(self._path):
            if not isinstance(row, dict):
                continue
            if aggregate_id and row.get("aggregate_id") != aggregate_id:
                continue
            if correlation_id and row.get("correlation_id") != correlation_id:
                continue
            try:
                yield DomainEvent(**row)
            except Exception:
                continue
            count += 1
            if count >= limit:
                break

    def load_aggregate_events(self, aggregate_id: str) -> list[DomainEvent]:
        """Load all events for aggregate in deterministic sequence order."""
        events = list(self.iter_events(aggregate_id=aggregate_id, limit=100_000))
        events.sort(key=lambda e: e.sequence)
        return events

    def invalidate_cache(self) -> None:
        """Provide invalidate cache behavior for toolkit workflows.

        Returns:
            None.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        self._sequence_cache = None


def append_domain_event(
    *,
    aggregate_id: str,
    aggregate_type: Literal["incident", "endpoint", "decision", "audit"],
    event_type: DomainEventType,
    correlation_id: str,
    payload: dict[str, Any] | None = None,
    causation_id: str | None = None,
    failure_domain: FailureDomainName | None = None,
    actor: str = "system",
    store: DomainEventStore | None = None,
) -> DomainEvent:
    """Convenience append with auto-assigned sequence."""
    st = store or DomainEventStore()
    seq = st.next_sequence(aggregate_id)
    event = DomainEvent(
        sequence=seq,
        aggregate_id=aggregate_id,
        aggregate_type=aggregate_type,
        event_type=event_type,
        correlation_id=correlation_id,
        causation_id=causation_id,
        failure_domain=failure_domain,
        actor=actor,
        payload=payload or {},
    )
    return st.append(event)

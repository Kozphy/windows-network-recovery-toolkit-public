"""Event deduplication and idempotency — gateway-side exactly-once accept semantics."""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from .models import FleetEventEnvelope, IdempotencyRecord

DedupOutcome = Literal["accepted", "duplicate", "conflict"]


@dataclass(frozen=True)
class DedupDecision:
    """Represent DedupDecision data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    outcome: DedupOutcome
    event_id: str
    reason: str = ""
    existing_event_id: str | None = None


class IdempotencyStore(ABC):
    """Pluggable dedup store — in-memory (dev), Redis (staging), Postgres (prod)."""

    @abstractmethod
    def check_and_record(self, envelope: FleetEventEnvelope) -> DedupDecision:
        """Atomically check idempotency key and record if new."""

    @abstractmethod
    def get_by_key(
        self, tenant_id: str, producer_id: str, idempotency_key: str
    ) -> IdempotencyRecord | None:
        """Get by key for toolkit workflows.

        Args:
            tenant_id: Value supplied by the caller for tenant id.
            producer_id: Value supplied by the caller for producer id.
            idempotency_key: Value supplied by the caller for idempotency key.

        Returns:
            None.

        Side effects:
            None.
        """
        pass


class InMemoryIdempotencyStore(IdempotencyStore):
    """Thread-safe in-memory store for tests and local mode."""

    def __init__(self, *, ttl_seconds: float = 72 * 3600) -> None:
        """Initialize the InMemoryIdempotencyStore instance.

        Args:
            ttl_seconds: Value supplied by the caller for ttl seconds.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._keys: dict[tuple[str, str, str], IdempotencyRecord] = {}

    def _purge_expired(self) -> None:
        now = time.monotonic()
        if not hasattr(self, "_insert_times"):
            self._insert_times: dict[tuple[str, str, str], float] = {}
        expired = [k for k, t in self._insert_times.items() if now - t > self._ttl]
        for k in expired:
            self._keys.pop(k, None)
            self._insert_times.pop(k, None)

    def check_and_record(self, envelope: FleetEventEnvelope) -> DedupDecision:
        """Provide check and record behavior for toolkit workflows.

        Args:
            envelope: Value supplied by the caller for envelope.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        if not envelope.idempotency_key:
            return DedupDecision(
                outcome="conflict", event_id=envelope.event_id, reason="missing_idempotency_key"
            )

        key = (envelope.tenant.tenant_id, envelope.producer_id, envelope.idempotency_key)
        with self._lock:
            self._purge_expired()
            existing = self._keys.get(key)
            if existing:
                if existing.event_id == envelope.event_id:
                    return DedupDecision(
                        outcome="duplicate",
                        event_id=envelope.event_id,
                        reason="retry_same_event_id",
                        existing_event_id=existing.event_id,
                    )
                return DedupDecision(
                    outcome="conflict",
                    event_id=envelope.event_id,
                    reason="idempotency_key_reuse_different_payload",
                    existing_event_id=existing.event_id,
                )
            rec = IdempotencyRecord(
                tenant_id=envelope.tenant.tenant_id,
                producer_id=envelope.producer_id,
                idempotency_key=envelope.idempotency_key,
                event_id=envelope.event_id,
            )
            self._keys[key] = rec
            if not hasattr(self, "_insert_times"):
                self._insert_times = {}
            self._insert_times[key] = time.monotonic()
            return DedupDecision(outcome="accepted", event_id=envelope.event_id)

    def get_by_key(
        self, tenant_id: str, producer_id: str, idempotency_key: str
    ) -> IdempotencyRecord | None:
        """Get by key for toolkit workflows.

        Args:
            tenant_id: Value supplied by the caller for tenant id.
            producer_id: Value supplied by the caller for producer id.
            idempotency_key: Value supplied by the caller for idempotency key.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return self._keys.get((tenant_id, producer_id, idempotency_key))

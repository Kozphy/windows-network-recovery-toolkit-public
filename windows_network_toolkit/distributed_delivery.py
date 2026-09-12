"""Deterministic delivery contracts for distributed-systems portfolio scenarios.

Module responsibility:
    Model the delivery semantics that matter before selecting a message
    broker (Kafka, Redis, NATS, cloud queue): idempotency, bounded-queue
    back-pressure, transient vs permanent failure classification, retry
    routing, and dead-letter accumulation.  All types are in-memory and
    dependency-free.

System placement:
    Portfolio / interview artefact demonstrating distributed-systems design
    understanding.  Not wired into the live analytics pipeline or any
    production ingest path.

Key invariants:
    * ``IdempotencyLedger`` models *effect completion*, not message receipt —
      a retried message may be processed again until the side effect is
      durably recorded.
    * ``BoundedDeliveryQueue`` enforces a hard ``capacity`` limit; attempting
      to enqueue beyond capacity returns ``BACKPRESSURE`` without blocking.
    * ``DeliveryProcessor.process`` returns ``DUPLICATE`` for any envelope
      whose ``idempotency_key`` is already in the ledger; the side effect is
      not called again.
    * ``TransientDeliveryError`` triggers retry up to ``RetryPolicy.max_attempts``;
      ``PermanentDeliveryError`` routes directly to the dead-letter queue.

Side effects:
    All state is in-memory.  No I/O, network calls, or OS interactions.

Failure modes:
    ``ValueError`` raised by ``RetryPolicy`` and ``BoundedDeliveryQueue``
    constructors for invalid configuration values.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Generic, TypeVar

T = TypeVar("T")


class DeliveryDisposition(str, Enum):
    """Final outcome of a single ``DeliveryProcessor.process`` call.

    Attributes:
        ACK: Side effect completed successfully; idempotency key recorded.
        RETRY: Transient failure; envelope re-queued for another attempt.
        DEAD_LETTER: Exhausted retries or permanent failure; routed to DLQ.
        DUPLICATE: Idempotency key already completed; side effect skipped.
        BACKPRESSURE: Retry queue full; caller must handle back-pressure.
    """

    ACK = "ACK"
    RETRY = "RETRY"
    DEAD_LETTER = "DEAD_LETTER"
    DUPLICATE = "DUPLICATE"
    BACKPRESSURE = "BACKPRESSURE"


@dataclass(frozen=True)
class DeliveryEnvelope(Generic[T]):
    """Immutable wrapper carrying a payload through the delivery pipeline.

    Attributes:
        event_id: Stable unique identifier for the logical event.
        idempotency_key: Key used by ``IdempotencyLedger`` to detect
            duplicate side-effect executions.  Typically equal to
            ``event_id`` but may differ when multiple events share an effect.
        payload: The data to be processed.
        attempt: Current delivery attempt number, starting at 1.
    """

    event_id: str
    idempotency_key: str
    payload: T
    attempt: int = 1

    def next_attempt(self) -> DeliveryEnvelope[T]:
        """Return a new envelope with ``attempt`` incremented by 1."""
        return DeliveryEnvelope(
            event_id=self.event_id,
            idempotency_key=self.idempotency_key,
            payload=self.payload,
            attempt=self.attempt + 1,
        )


@dataclass(frozen=True)
class RetryPolicy:
    """Configuration for transient-failure retry behaviour.

    Attributes:
        max_attempts: Maximum total delivery attempts before an envelope is
            routed to the dead-letter queue (default 3, must be ≥ 1).
    """

    max_attempts: int = 3

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")


@dataclass
class IdempotencyLedger:
    """Tracks completed side effects by stable idempotency key.

    This deliberately models *effect completion*, not message receipt. A retried
    delivery may be processed again until the side effect is durably recorded.
    """

    completed_keys: set[str] = field(default_factory=set)

    def is_completed(self, key: str) -> bool:
        """Return ``True`` when the side effect for ``key`` has been durably recorded."""
        return key in self.completed_keys

    def mark_completed(self, key: str) -> None:
        """Record that the side effect for ``key`` completed successfully."""
        self.completed_keys.add(key)


@dataclass
class BoundedDeliveryQueue(Generic[T]):
    """In-memory FIFO queue with a hard capacity ceiling for back-pressure modelling.

    Attributes:
        capacity: Maximum number of envelopes the queue may hold (must be ≥ 1).
    """

    capacity: int
    _items: deque[DeliveryEnvelope[T]] = field(default_factory=deque)

    def __post_init__(self) -> None:
        if self.capacity < 1:
            raise ValueError("capacity must be >= 1")

    @property
    def depth(self) -> int:
        """Current number of envelopes waiting in the queue."""
        return len(self._items)

    @property
    def utilization(self) -> float:
        """Queue fill fraction in the range [0.0, 1.0]."""
        return self.depth / self.capacity

    def try_put(self, item: DeliveryEnvelope[T]) -> DeliveryDisposition:
        """Attempt to enqueue ``item``.

        Returns:
            ``ACK`` on success; ``BACKPRESSURE`` when the queue is at capacity.
        """
        if self.depth >= self.capacity:
            return DeliveryDisposition.BACKPRESSURE
        self._items.append(item)
        return DeliveryDisposition.ACK

    def get(self) -> DeliveryEnvelope[T] | None:
        """Dequeue and return the oldest envelope, or ``None`` when empty."""
        if not self._items:
            return None
        return self._items.popleft()


@dataclass
class DeliveryOutcome(Generic[T]):
    """Result of a single ``DeliveryProcessor.process`` call.

    Attributes:
        disposition: How the envelope was handled (ACK, RETRY, etc.).
        envelope: The envelope that was processed (may be the retry copy).
        error: Exception message when disposition is not ACK or DUPLICATE;
            ``None`` on success.
    """

    disposition: DeliveryDisposition
    envelope: DeliveryEnvelope[T]
    error: str | None = None


class TransientDeliveryError(RuntimeError):
    """Retryable processing failure; the envelope will be re-queued if attempts remain."""


class PermanentDeliveryError(RuntimeError):
    """Non-retryable processing failure; the envelope is routed directly to the DLQ."""


@dataclass
class DeliveryProcessor(Generic[T]):
    """Stateful processor that applies idempotency, retry, and dead-letter routing.

    Attributes:
        retry_policy: Controls how many attempts are made before dead-lettering.
        ledger: Tracks which idempotency keys have completed side effects.
        retry_queue: Bounded FIFO for envelopes awaiting retry.
        dead_letter_queue: Accumulates envelopes that exhausted retries or
            encountered permanent failures.
    """

    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    ledger: IdempotencyLedger = field(default_factory=IdempotencyLedger)
    retry_queue: BoundedDeliveryQueue[T] = field(
        default_factory=lambda: BoundedDeliveryQueue(capacity=100)
    )
    dead_letter_queue: list[DeliveryEnvelope[T]] = field(default_factory=list)

    def process(
        self,
        envelope: DeliveryEnvelope[T],
        side_effect: Callable[[T], None],
    ) -> DeliveryOutcome[T]:
        """Process one delivery envelope through the idempotency + retry pipeline.

        Args:
            envelope: Envelope to process.
            side_effect: Callable that executes the desired effect for
                ``envelope.payload``.  Must raise ``TransientDeliveryError``
                for retryable failures or ``PermanentDeliveryError`` for
                non-retryable ones.

        Returns:
            ``DeliveryOutcome`` describing how the envelope was handled.
            Possible dispositions: ``ACK``, ``RETRY``, ``DEAD_LETTER``,
            ``DUPLICATE``, ``BACKPRESSURE``.
        """
        if self.ledger.is_completed(envelope.idempotency_key):
            return DeliveryOutcome(DeliveryDisposition.DUPLICATE, envelope)

        try:
            side_effect(envelope.payload)
        except PermanentDeliveryError as exc:
            self.dead_letter_queue.append(envelope)
            return DeliveryOutcome(
                DeliveryDisposition.DEAD_LETTER,
                envelope,
                error=str(exc),
            )
        except TransientDeliveryError as exc:
            if envelope.attempt >= self.retry_policy.max_attempts:
                self.dead_letter_queue.append(envelope)
                return DeliveryOutcome(
                    DeliveryDisposition.DEAD_LETTER,
                    envelope,
                    error=str(exc),
                )
            retry_envelope = envelope.next_attempt()
            queued = self.retry_queue.try_put(retry_envelope)
            if queued is DeliveryDisposition.BACKPRESSURE:
                return DeliveryOutcome(
                    DeliveryDisposition.BACKPRESSURE,
                    envelope,
                    error=str(exc),
                )
            return DeliveryOutcome(
                DeliveryDisposition.RETRY,
                retry_envelope,
                error=str(exc),
            )

        self.ledger.mark_completed(envelope.idempotency_key)
        return DeliveryOutcome(DeliveryDisposition.ACK, envelope)

"""Retry, circuit breaker, backpressure, and graceful degradation."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

T = TypeVar("T")


@dataclass
class CircuitBreaker:
    """Simple circuit breaker for external probes (Sysmon, ETW, network)."""

    failure_threshold: int = 5
    recovery_timeout_seconds: float = 30.0
    _failures: int = 0
    _opened_at: float | None = None
    state: str = "closed"

    def call(self, fn: Callable[[], T], *, fallback: T | None = None) -> T | None:
        """Provide call behavior for toolkit workflows.

        Args:
            fn: Value supplied by the caller for fn.
            fallback: Value supplied by the caller for fallback.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        if self.state == "open":
            if (
                self._opened_at
                and (time.monotonic() - self._opened_at) > self.recovery_timeout_seconds
            ):
                self.state = "half_open"
            else:
                return fallback
        try:
            result = fn()
            if self.state == "half_open":
                self.state = "closed"
                self._failures = 0
            return result
        except Exception:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self.state = "open"
                self._opened_at = time.monotonic()
            return fallback


@dataclass
class BackpressureQueue:
    """Drop oldest when over capacity — graceful degradation for event ingest."""

    max_size: int = 10_000
    _dropped: int = 0
    _items: list[Any] = field(default_factory=list)

    def push(self, item: Any) -> bool:
        """Provide push behavior for toolkit workflows.

        Args:
            item: Value supplied by the caller for item.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        if len(self._items) >= self.max_size:
            self._items.pop(0)
            self._dropped += 1
        self._items.append(item)
        return True

    @property
    def dropped_count(self) -> int:
        """Provide dropped count behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return self._dropped


def retry_with_backoff(
    fn: Callable[[], T],
    *,
    max_attempts: int = 3,
    base_delay: float = 0.25,
) -> T:
    """Retry transient failures with exponential backoff."""
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt < max_attempts - 1:
                time.sleep(base_delay * (2**attempt))
    assert last_exc is not None
    raise last_exc

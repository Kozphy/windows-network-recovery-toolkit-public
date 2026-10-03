"""ETW ingestion boundary (prototype stub — no kernel session lifecycle).

Module responsibility:
    Define Protocol + in-memory implementations so callers can defer real Windows ETW wiring while
    still typing attribution pipelines uniformly.

System placement:
    Optional branch inside :mod:`evidence.attribution_engine`; absent rows keep attribution ``heuristic`` tier unless other telemetry compensates.

Key invariants:
    * ``StubETWReader`` never performs native calls—it only echoes injected batches suitable for pytest.
    * ``ETWProviderConfig`` retains metadata scaffolding only—GUID strings unvalidated against OS catalogs.

Concurrency:
    ``StubETWReader.drain_batches`` mutates queue—single-thread demos assume no concurrent drains.

Raises:
    None from stub reader; eventual real adapter should documentHRESULT failures explicitly.

Safety Notes:
    Future native ETW wrappers must elevate privileges thoughtfully—outside scope of stub.

Audit Notes:
    Persist raw ETW JSON only under operator-reviewed paths; stub currently prevents accidental egress by omission.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol


class ETWProviderConfig:
    """Lightweight descriptive record for would-be ETW provider wiring.

    Args:
        name: Friendly provider label (informative logging only).
        guid: Provider GUID placeholder—empty string tolerated until adapters fill real values.

    Raises:
        None.
    """

    def __init__(self, name: str, guid: str = "") -> None:
        """Initialize the ETWProviderConfig instance.

        Args:
            name: Value supplied by the caller for name.
            guid: Value supplied by the caller for guid.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self.name = name
        self.guid = guid


@dataclass
class ETWTraceBatch:
    """Grouped ETW-ish dict events tagged by originating provider nickname.

    Attributes:
        provider: Logical grouping string (telemetry provenance—not necessarily ETW manifest name).
        events: Loose JSON-shaped dict payloads interpreted downstream by heuristic filters.
    """

    provider: str
    events: list[dict[str, Any]] = field(default_factory=list)


class ETWReader(Protocol):
    """Typing contract future Windows producers must satisfy."""

    def drain_batches(self, *, max_events: int = 500) -> Sequence[ETWTraceBatch]:
        """Provide drain batches behavior for toolkit workflows.

        Args:
            max_events: Value supplied by the caller for max events.

        Returns:
            None.

        Side effects:
            None.
        """
        ...


class StubETWReader:
    """Test double draining explicit batches queued via :meth:`push_batch`.

    Args:
        seed_batches: Optional initial deque contents for deterministic setup.

    Note:
        ``max_events`` parameter accepted for Protocol parity but presently ignored—extend when buffering large captures.
    """

    def __init__(self, *, seed_batches: Sequence[ETWTraceBatch] | None = None) -> None:
        """Initialize the StubETWReader instance.

        Args:
            seed_batches: Value supplied by the caller for seed batches.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self._batches: list[ETWTraceBatch] = list(seed_batches or [])

    def push_batch(self, batch: ETWTraceBatch) -> None:
        """Enqueue another batch drained on next drain call."""

        self._batches.append(batch)

    def drain_batches(self, *, max_events: int = 500) -> Sequence[ETWTraceBatch]:
        """Provide drain batches behavior for toolkit workflows.

        Args:
            max_events: Value supplied by the caller for max events.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        _ = max_events
        out = list(self._batches)
        self._batches.clear()
        return out


def etw_event_suggests_proxy_writer(ev: dict[str, Any]) -> bool:
    """Cheap keyword gate for provisional ETW JSON rows.

    Args:
        ev: Arbitrary-shaped row—values stringified sequentially.

    Returns:
        True when flattened lowercase text references ``proxy`` with ``registry`` or ``wininet``.

    Limitations:
        High false-positive rate acceptable for exploratory scoring boosts only—never sole conviction signal.
    """

    blob = " ".join(str(v) for v in ev.values()).lower()
    return "proxy" in blob and ("registry" in blob or "wininet" in blob)

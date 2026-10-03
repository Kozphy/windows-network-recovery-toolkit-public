"""ETW ingestion stub — facade over :mod:`evidence.etw_reader` (no kernel session lifecycle).

Module responsibility:
    Expose ``StubETWReader`` + keyword helpers for demos without implying production ETW subscriptions ship here.

System placement:
    Optional branch when ETW-shaped dict lists accompany attribution fixtures.

Side effects:
    ``StubETWReader`` mutates internal batch deque when pushing/draining—single-threaded demos assume no concurrency.

Audit Notes:
    Future native ETW adapters must document privilege elevation + HRESULT mapping separately—this facade prevents accidental claims of kernel proof in fixtures.
"""

from __future__ import annotations

from evidence.etw_reader import (
    ETWProviderConfig,
    ETWReader,
    ETWTraceBatch,
    StubETWReader,
    etw_event_suggests_proxy_writer,
)

__all__ = [
    "ETWProviderConfig",
    "ETWReader",
    "ETWTraceBatch",
    "StubETWReader",
    "etw_event_suggests_proxy_writer",
]

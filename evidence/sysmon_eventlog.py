"""Sysmon Event ID 13–shaped exporter rows — thin facade over :mod:`evidence.sysmon_reader`.

Module responsibility:
    Stable import surface for offline Sysmon-shaped dict parsing used in pytest and ``GET /platform/attribution``
    staging contexts.

System placement:
    Upstream of :func:`~evidence.attribution_engine.build_attribution` when ``sysmon_events`` sequences are supplied.

Side effects:
    None at import—parsers operate on dict inputs only.

Failure modes:
    :func:`~evidence.sysmon_reader.parse_sysmon_row` returns ``None`` for non-matching IDs—callers filter explicitly.
"""

from __future__ import annotations

from evidence.sysmon_reader import (
    SysmonRegistrySetEvent,
    parse_sysmon_row,
    registry_event_concerns_internet_settings,
)

__all__ = [
    "SysmonRegistrySetEvent",
    "parse_sysmon_row",
    "registry_event_concerns_internet_settings",
]

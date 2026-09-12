"""Windows Event Log / Sysmon proxy-event collector facade.

Module responsibility:
    Collect Sysmon proxy-related registry events from the Windows Event Log
    and return a normalised evidence dict.  Accepts an injectable ``run``
    callable to allow deterministic fixture-based tests without touching the
    live Windows Event Log.

System placement:
    Called by the analytics pipeline's signal-collection phase.  The actual
    Sysmon event parsing lives in
    ``src.proxy_guard.sysmon_attribution.collect_sysmon_proxy_events``; this
    module only dispatches the call and serialises the results.

Key invariants:
    * Row objects returned by the underlying collector are serialised via
      ``to_dict()`` when available; plain dicts are passed through unchanged.
    * The ``max_events`` cap is applied both to the query and to the returned
      ``events`` list.

Side effects:
    Reads the Windows Microsoft-Windows-Sysmon/Operational event channel when
    called without an injectable ``run``.  No writes or side effects otherwise.

Failure modes:
    Exceptions from ``collect_sysmon_proxy_events`` propagate to the caller.
    On non-Windows hosts the underlying implementation may return an empty
    list with a platform-limitation note.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def collect_eventlog_signals(
    *,
    run: Callable[..., Any] | None = None,
    max_events: int = 25,
) -> dict[str, Any]:
    """Collect Sysmon proxy-related registry events from the Windows Event Log.

    Delegates to ``collect_sysmon_proxy_events``; each returned row is
    serialised to a plain dict via ``to_dict()`` when the method exists.

    Args:
        run: Optional subprocess runner forwarded to the underlying collector.
            Pass a fixture callable in tests to avoid live Event Log reads.
        max_events: Maximum number of events to query and return (default 25).

    Returns:
        Dict with keys ``event_count`` (int), ``events`` (list of row dicts
        capped at ``max_events``), and ``source``
        (``"sysmon_operational"``).
    """
    from src.proxy_guard.sysmon_attribution import collect_sysmon_proxy_events

    kwargs: dict[str, Any] = {"max_events": max_events}
    if run is not None:
        kwargs["run"] = run
    rows = collect_sysmon_proxy_events(**kwargs)

    def _serialize_row(row: Any) -> Any:
        if isinstance(row, dict):
            return row
        to_dict = getattr(row, "to_dict", None)
        return to_dict() if callable(to_dict) else row

    serialized = [_serialize_row(row) for row in rows]
    return {
        "event_count": len(serialized),
        "events": serialized[:max_events],
        "source": "sysmon_operational",
    }

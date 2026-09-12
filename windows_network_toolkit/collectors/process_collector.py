"""Process inventory collector facade — delegates to src/proxy_guard/process_inventory.

Module responsibility:
    Collect a snapshot of running Win32 processes and apply the existing
    heuristic candidate filter to identify processes that may be acting as a
    proxy actor.  Returns a normalised evidence dict safe for JSON
    serialisation.

System placement:
    Called by the analytics pipeline's signal-collection phase.  The process
    enumeration and heuristic candidate scoring live in
    ``src.proxy_guard.process_inventory``; this module only dispatches and
    shapes the output.

Key invariants:
    * At most ``max_rows`` candidate rows are included in the result.
    * Each candidate is serialised via ``to_dict()`` when the method exists,
      or converted via ``dict()`` otherwise — keeping the caller
      implementation-agnostic.
    * Observation of a process in the candidate list is correlation only, not
      proof that the process wrote WinINET proxy settings.

Side effects:
    Invokes Win32 process enumeration (``WMI`` or ``psutil``) when called
    without an injectable ``run`` override.

Failure modes:
    Exceptions from ``capture_process_inventory`` or
    ``heuristic_proxy_actor_candidates`` propagate to the caller.  On
    non-Windows hosts the underlying implementation returns an empty list.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def collect_process_signals(
    *,
    run: Callable[..., Any] | None = None,
    max_rows: int = 50,
) -> dict[str, Any]:
    """Capture the running process inventory and heuristic proxy actor candidates.

    Delegates to ``capture_process_inventory`` for enumeration and
    ``heuristic_proxy_actor_candidates`` for candidate scoring.

    Args:
        run: Optional subprocess runner forwarded to the underlying collector.
            Pass a fixture callable in tests to avoid live Win32 queries.
        max_rows: Maximum number of candidate rows to include in the result
            (default 50).

    Returns:
        Dict with keys ``process_count`` (total processes enumerated),
        ``candidates`` (list of row dicts, length ≤ ``max_rows``), and
        ``source`` (``"win32_process_inventory"``).
    """
    from src.proxy_guard.process_inventory import (
        capture_process_inventory,
        heuristic_proxy_actor_candidates,
    )

    kwargs: dict[str, Any] = {}
    if run is not None:
        kwargs["run"] = run
    inventory = capture_process_inventory(**kwargs)
    candidates = heuristic_proxy_actor_candidates(inventory, max_rows=max_rows)
    return {
        "process_count": len(inventory),
        "candidates": [
            c.to_dict() if hasattr(c, "to_dict") else dict(c) for c in candidates[:max_rows]
        ],
        "source": "win32_process_inventory",
    }

"""Audit timeline builder from ``.audit/`` JSONL files.

Module responsibility:
    Reads all JSONL audit records matching a glob pattern, sorts them by
    ``timestamp_utc``, and returns a chronological timeline with a command-grouped
    event-count summary.  This provides the temporal evidence chain for
    operator review and report rendering.

System placement:
    Called by the ``timeline`` CLI command and by ``report.py`` indirectly via
    ``read_audit_logs``.

Key invariants:
    Records without a ``timestamp_utc`` field sort to the beginning of the
    timeline (empty-string comparison).  The returned ``timeline`` list preserves
    all original record fields and is not filtered or redacted.

Side effects:
    Reads JSONL files matching ``audit_dir_pattern`` from the ``.audit/``
    directory (or the path configured in ``audit_store``).

Failure modes:
    Malformed JSONL lines are silently skipped by ``read_audit_logs``.  If no
    files match the pattern an empty timeline is returned.
"""

from __future__ import annotations

from typing import Any

from windows_network_toolkit.audit_store import read_audit_logs


def build_proxy_timeline(*, audit_dir_pattern: str = "*.jsonl") -> dict[str, Any]:
    """Read and chronologically sort all JSONL audit records.

    Args:
        audit_dir_pattern: Glob pattern passed to ``read_audit_logs`` to select
            which JSONL files to include.  Defaults to ``"*.jsonl"`` (all files).

    Returns:
        A dict with:

        - ``event_count`` (int): Total number of valid records found.
        - ``timeline`` (list[dict]): Records sorted ascending by ``timestamp_utc``.
        - ``groups`` (dict[str, int]): Event counts keyed by ``command`` or
          ``event`` field value; unknown events map to the key ``"unknown"``.

    Side effects:
        Reads JSONL files from disk via ``read_audit_logs``.
    """
    rows = read_audit_logs(pattern=audit_dir_pattern)
    ordered = sorted(rows, key=lambda r: str(r.get("timestamp_utc") or ""))
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in ordered:
        cmd = str(row.get("command") or row.get("event") or "unknown")
        groups.setdefault(cmd, []).append(row)
    return {
        "event_count": len(ordered),
        "timeline": ordered,
        "groups": {k: len(v) for k, v in groups.items()},
    }

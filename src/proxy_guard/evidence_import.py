"""Optional Sysmon/Procmon CSV/JSONL imports for corroborating HKCU Internet Settings activity.

Module responsibility:
    Scan operator-supplied exports for rows mentioning the WinINET HKCU subtree string
    ``Internet Settings``, normalize lightweight hints (PID/process/time snippets), and return bounded
    **additive** confidence boosts for :func:`~src.proxy_guard.change_attribution.attribute_proxy_change`.

System placement:
    Invoked indirectly by CLI ``proxy-watch --evidence-csv`` →
    :func:`~src.proxy_guard.evidence_import.confidence_boost_from_csv`; Sysmon helper available for future
    wiring but shares the same conservative boost philosophy.

Key invariants:
    * Parsers are read-only toward the toolkit—never mutate exported evidence files.

Input assumptions:
    * CSV layouts follow common Procmon column labels (``Path``, ``detail``, ``Process Name``, ``PID``, …)—
      heuristic column matching tolerates synonyms (see ``col(...)`` helpers).

Output guarantees:
    * Boost masses are deterministic given identical inputs; callers clamp totals when merging with heuristic
      scores.

Side effects:
    * Reads files via UTF-8 with ``errors="replace"`` (no writes).

Audit Notes:
    * Boost values **do not** prove registry authorship—they only tag that an export row referenced the
      target path substring. Correlate originals with SOC timelines when forensic certainty is required.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

_INTERNET_SETTINGS = re.compile(r"Internet Settings", re.I)


def parse_procmon_registry_csv(path: Path) -> list[dict[str, Any]]:
    """Extract rows whose path/detail column mentions ``Internet Settings`` (WinINET subtree).

    Args:
        path: Readable CSV export (typically Procmon registry filter saved as CSV).

    Returns:
        List of dictionaries with stable keys ``source``, ``time_hint``, ``process_name_hint``,
        ``pid_hint``, ``registry_hint`` (truncated to 2048 chars). Empty list when headers are missing or
        no rows match.

    Side effects:
        Opens *path* for sequential read-only access.

    Failure modes:
        Malformed CSV rows yield partial extraction; unmatched encodings degrade via ``errors="replace"``.

    Constraints:
        Substring matching is case-insensitive; false positives occur if unrelated registry paths reuse the
        same phrase elsewhere.
    """
    hits: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            return hits
        field_map = {h.lower(): h for h in reader.fieldnames}

        def col(*names: str) -> str | None:
            for n in names:
                key = field_map.get(n.lower())
                if key:
                    return key
            return None

        c_path = col("path", "detail", "object", "registry path")
        if c_path:
            target_field = c_path
        elif reader.fieldnames:
            target_field = reader.fieldnames[0]
        else:
            target_field = None

        c_img = col("process name", "image", "processname")
        c_pid = col("pid")
        c_time = col("time", "utc time", "time of day")

        for row in reader:
            probe = ""
            if target_field and isinstance(row.get(target_field), str):
                probe = row[target_field] or ""
            if probe and _INTERNET_SETTINGS.search(probe):
                pid_s = ""
                if c_pid:
                    pid_s = str(row.get(c_pid or "", "") or "")
                hits.append(
                    {
                        "source": path.name,
                        "time_hint": str(row.get(c_time or "", "") or ""),
                        "process_name_hint": str(row.get(c_img or "", "") or ""),
                        "pid_hint": pid_s.strip(),
                        "registry_hint": probe[:2048],
                    },
                )

    return hits


def confidence_boost_from_csv(path: Path) -> tuple[float, list[dict[str, Any]]]:
    """Combine Procmon-derived hits into a capped additive confidence float for attribution.

    Args:
        path: CSV readable by :func:`parse_procmon_registry_csv`.

    Returns:
        ``(mass, hits)`` where ``mass`` = ``min(0.08 * len(hits), 0.24)`` and ``hits`` echoes parsed rows.

    Side effects:
        Reads *path* only.

    Engineering Notes:
        Linear scaling caps avoid double-counting many duplicate export lines into certainty—callers still
        merge with probabilistic heuristic scores capped at ``1.0``.
    """

    hits = parse_procmon_registry_csv(path)
    if not hits:
        return 0.0, []
    mass = min(0.08 * len(hits), 0.24)
    return mass, hits


def parse_sysmon_jsonl(path: Path) -> tuple[float, list[dict[str, Any]]]:
    """Scan JSON-lines Sysmon-style exports whose serialized JSON mentions ``Internet Settings``.

    Args:
        path: UTF-8 text file with one JSON object per non-empty line (tolerant parser).

    Returns:
        Tuple ``(boost, hits)`` where ``hits`` retains up to **50** raw dict blobs that matched after
        full-document ``json.dumps`` substring search; ``boost`` = ``min(0.06 * len(hits), 0.18)``.

    Side effects:
        Reads entire file into memory via :meth:`path.read_text`—avoid multi-gigabyte dumps.

    Failure modes:
        Lines that fail JSON decoding are skipped silently; unreadable paths return ``(0.0, [])``.

    Constraints:
        Because matching runs on dumped JSON strings, minimally structured-but-spurious hits remain possible;
        reviewer must inspect ``hits``.
    """

    hits: list[dict[str, Any]] = []
    raw = ""
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0.0, []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        blob: dict[str, Any] | None
        try:
            obj = json.loads(line)
            blob = obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            blob = None
        if not blob:
            continue
        text = json.dumps(blob, ensure_ascii=False)
        if not _INTERNET_SETTINGS.search(text):
            continue
        hits.append(blob)
        if len(hits) >= 50:
            break
    boost = min(0.06 * len(hits), 0.18)
    return boost, hits

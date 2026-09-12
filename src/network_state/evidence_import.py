"""Optional external evidence import (Procmon/Sysmon-style CSV) — never installs tracers."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

from ..core.time_utils import utc_now_iso
from .paths import evidence_jsonl

_INTERNET_SETTINGS = re.compile(r"Internet Settings", re.I)


def parse_procmon_like_csv(path: Path) -> list[dict[str, Any]]:
    """Parse a CSV with headers similar to Procmon (case-insensitive column names).

    Returns rows touching WinINET HKCU paths when ``Path`` column is present.
    """

    out: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames:
            return out
        fields = {h.lower().strip(): h for h in reader.fieldnames if h}

        def col(*candidates: str) -> str | None:
            for c in candidates:
                k = fields.get(c.lower())
                if k:
                    return k
            return None

        c_time = col("time of day", "time", "timestamp")
        c_proc = col("process name", "image", "processname")
        c_pid = col("pid", "process id")
        c_op = col("operation", "event")
        c_path = col("path", "object", "registry path")
        c_detail = col("detail", "details", "message")

        for row in reader:
            raw_path = ""
            if c_path and row.get(c_path):
                raw_path = str(row[c_path])
            if not raw_path or not _INTERNET_SETTINGS.search(raw_path):
                continue
            out.append(
                {
                    "time": str(row.get(c_time or "", "")),
                    "process_name": str(row.get(c_proc or "", "")),
                    "pid": str(row.get(c_pid or "", "")),
                    "operation": str(row.get(c_op or "", "")),
                    "registry_path": raw_path,
                    "detail": str(row.get(c_detail or "", ""))[:2000],
                },
            )
    return out


def append_evidence_rows(repo_root: Path, rows: list[dict[str, Any]], *, source_file: str) -> int:
    """Append normalized evidence lines for correlation with drift events."""

    path = evidence_jsonl(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("a", encoding="utf-8") as fh:
        for r in rows:
            rec = {
                "schema_version": 1,
                "imported_at_utc": utc_now_iso(),
                "source_file": source_file,
                "row": r,
            }
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            count += 1
    return count


def match_evidence_to_drift_hint(
    rows: list[dict[str, Any]],
    *,
    drift_detected_at_iso: str,
) -> list[dict[str, Any]]:
    """Very loose time correlation — same minute prefix or nearest rows (demo linkage)."""

    hints: list[dict[str, Any]] = []
    prefix = drift_detected_at_iso[:16]
    for r in rows[:500]:
        t = str(r.get("time") or "")
        if prefix and len(t) >= 8 and (prefix in t or t in drift_detected_at_iso):
            hints.append(r)
    return hints[:20]

"""JSON-lines structured logging for Proxy Guard (machine-parseable, consistent schema).

Module responsibility:
    Emit single-line JSON log records to stderr and/or append-only files with stable
    ``schema_version=1`` keys for probe timing and guard lifecycle events.

System placement:
    Used by :mod:`guard`, :mod:`probes`, and watch tooling; distinct from human stderr
    banners in :mod:`human_report`.

Key invariants:
    * Timestamps are UTC ISO-8601 via :mod:`core.time_utils`.
    * ``extra`` fields merge at top level — callers must avoid clobbering reserved keys.

Side effects:
    Appends UTF-8 lines when ``file_path`` set; writes to ``stream`` when provided.

Idempotency:
    Each emit is independent; no deduplication.

Audit Notes:
    Pair ``registry_probe_complete`` rows with ``registry_change_detected`` in the same
    JSONL tail when reconstructing incident timelines.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO

from ..core.time_utils import utc_now_iso

_SCHEMA_VERSION = "1"


def _append_file(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)
        fh.write("\n")


def emit_structured_log(
    *,
    logger: str,
    level: str,
    event: str,
    stream: TextIO | None = None,
    file_path: Path | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Emit one JSON object (single line) for operators and log aggregators.

    Schema (stable keys):
        ``schema_version``, ``timestamp``, ``logger``, ``level``, ``event``, plus any
        ``extra`` fields.

    Each invocation writes one line to ``sys.stderr`` (or ``stream``) and, when
    ``file_path`` is set, duplicates the same line to that append-only path.
    """
    row: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION,
        "timestamp": utc_now_iso(),
        "logger": logger,
        "level": level.upper(),
        "event": event,
    }
    if extra:
        for k, v in extra.items():
            row[k] = v
    line = json.dumps(row, ensure_ascii=False, default=str)
    out = stream if stream is not None else sys.stderr
    out.write(line + "\n")
    out.flush()
    if file_path is not None:
        _append_file(file_path, line)
    return row

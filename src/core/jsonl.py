"""Append-only newline-delimited JSON helpers (UTF-8, no pretty printing).

System placement:
    Consumed by ``src.logging`` audit/feedback paths and related CLI flows that persist one
    JSON record per line under ``logs/``.

Schema / validation:
    Callers supply ``dict[str, Any]`` payloads; this module does not validate keys or strip
    secrets before writing.

Mutability / staleness:
    Readers must tolerate partially written final lines after crashes and concurrent
    appenders—skip malformed lines rather than assuming atomic file replacement.

Each caller owns schema validation; this module only guarantees one JSON object per line.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    """Append ``payload`` as a single UTF-8 JSON line, creating parent dirs on demand.

    Args:
        path: Target ``.jsonl`` file (append mode).
        payload: JSON-serializable mapping (``str`` keys recommended).

    Side effects:
        Creates ``path.parent`` directories; opens file in append mode without advisory locking.

    Audit Notes:
        Corrupt or partially written lines imply concurrent writers or abrupt process kill;
        tail parsers should skip invalid JSON lines rather than failing closed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(payload, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")

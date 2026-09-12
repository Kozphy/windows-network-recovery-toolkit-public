"""Append-only JSONL event bus with schema-version validation and tolerant readers.

Module responsibility:
    Append normalized platform events to ``platform_data/normalized_events.jsonl`` (or
    caller path) with optional :class:`~platform_core.events.NormalizedEvent` validation.

System placement:
    Optional platform prototype layer; distinct from toolkit ``logs/events.jsonl`` in
    :mod:`platform_core.event_store`.

Key invariants:
    * ``validate_schema_version`` rejects unknown ``schema_version`` values listed in
      :mod:`platform_core.events`.
    * Readers skip malformed JSON lines without raising.

Side effects:
    Creates parent directories; appends one UTF-8 JSON line per call.

Idempotency:
    Duplicate appends are intentional (event sourcing); consumers dedupe by event id
    if required.

Failure modes:
    Missing ``schema_version`` fails validation on append when enforced by caller.

Audit Notes:
    Pair bus rows with ``platform_data/audit.jsonl`` for remediation execute paths;
    schema mismatches surface as ``unsupported_schema_version`` in validation tuples.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from platform_core.events import SUPPORTED_SCHEMA_VERSIONS, NormalizedEvent
from platform_core.storage import platform_data_dir

DEFAULT_EVENTS_FILE = "normalized_events.jsonl"


def default_normalized_events_path() -> Path:
    """Default normalized events path for toolkit workflows.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return platform_data_dir() / DEFAULT_EVENTS_FILE


def validate_schema_version(raw: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate the validate schema version condition.

    Args:
        raw: Value supplied by the caller for raw.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    sv = raw.get("schema_version")
    if sv is None:
        return False, "missing_schema_version"
    if str(sv) not in SUPPORTED_SCHEMA_VERSIONS:
        return False, f"unsupported_schema_version:{sv}"
    return True, ""


def append_event(
    event: dict[str, Any] | NormalizedEvent,
    path: Path | None = None,
) -> Path:
    """Append one JSON line; validates ``schema_version`` when present."""

    tgt = path or default_normalized_events_path()
    tgt.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(event, NormalizedEvent):
        payload = event.model_dump(mode="json")
    else:
        payload = dict(event)
        ok, err = validate_schema_version(payload)
        if not ok:
            raise ValueError(err)

    line = json.dumps(payload, ensure_ascii=False) + "\n"
    with tgt.open("a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
    return tgt


def read_events(
    path: Path | None = None,
    *,
    limit: int = 500,
    event_type: str | None = None,
    min_severity: str | None = None,
    endpoint_id_hash: str | None = None,
    schema_version: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read recent events with optional filters; malformed lines become parse error rows.

    Returns:
        Tuple of ``(good_rows, parse_errors)`` where errors include ``line_no`` and ``detail``.
    """

    tgt = path or default_normalized_events_path()
    good: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if not tgt.is_file():
        return good, errors

    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_rank = sev_rank.get(min_severity or "info", 0)

    with tgt.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append({"line_no": line_no, "detail": str(exc), "raw": line[:200]})
                continue
            if not isinstance(obj, dict):
                errors.append({"line_no": line_no, "detail": "not_a_json_object"})
                continue

            ok, err = validate_schema_version(obj)
            if not ok:
                errors.append({"line_no": line_no, "detail": err, "raw": line[:200]})
                continue

            if event_type and obj.get("event_type") != event_type:
                continue
            if schema_version and str(obj.get("schema_version")) != schema_version:
                continue
            if endpoint_id_hash and obj.get("endpoint_id_hash") != endpoint_id_hash:
                continue
            if min_severity:
                if sev_rank.get(str(obj.get("severity") or "info"), 0) < min_rank:
                    continue

            good.append(obj)
            if len(good) >= limit:
                break

    return good, errors


def iter_event_lines(
    path: Path, *, on_error: Callable[[int, str], None] | None = None
) -> Iterator[dict[str, Any]]:
    """Stream-parse JSONL without loading entire file (newest order not guaranteed)."""

    if not path.is_file():
        return
    with path.open(encoding="utf-8") as handle:
        for idx, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                if on_error:
                    on_error(idx, str(exc))
                continue
            if isinstance(obj, dict):
                yield obj

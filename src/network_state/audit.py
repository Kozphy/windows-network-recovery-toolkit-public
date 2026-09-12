"""Append-only restore audit helpers for Network State Manager.

Rows land in ``logs/network_state_audit.jsonl`` complementary to unified Proxy Guard action logs.
Each invocation records deterministic schema_version + opaque ``detail`` blob produced by rollback previewers.

Key invariants:
    * Phases differentiate **intent** versus **observed argv outcomes** (`restore_pre_change`, `restore_post_change`).
    * ``detail`` may embed argv arrays even during dry-run (never executed).

Timezone:
    ``timestamp_utc`` uses UTC ISO timestamps from ``utc_now_iso``.

Audit Notes:
    If pre/post phases disagree, correlate with simultaneous ``logs/proxy_guard_actions.jsonl`` inserts and rerun
    diff against expected profile snapshots.

Raises:
    Propagates ``OSError`` / ``TypeError`` from JSON serialization when ``detail`` is not JSON-safe (callers must ensure).

Recovery guidance:
    Truncate malformed tail lines cautiously — consumers skip JSON decode failures but lose ordering context.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Literal

from ..core.time_utils import utc_now_iso
from .paths import audit_jsonl

Phase = Literal["restore_pre_change", "restore_post_change"]


def append_restore_audit(
    repo_root: Path,
    *,
    phase: Phase,
    name: str,
    dry_run: bool,
    preview_or_result: dict[str, Any],
) -> dict[str, Any]:
    """Append structured audit describing restore phase (argv-shaped previews allowed).

    Args:
        repo_root: Resolved toolkit checkout.
        phase: Enumeration preventing ambiguous merges when scanning JSONL sequentially.
        name: Snapshot profile correlate.
        dry_run:
            Mirrors CLI intent — ``True`` when restore APIs must not mutate registry / subprocesses.
        preview_or_result: Arbitrary rollback payload mirrored verbatim for auditors.

    Returns:
        Persisted audit row inclusive of UUID ``audit_id`` for downstream cross references.

    Side effects:
        Creates ``logs`` as needed and appends one newline-terminated JSON blob.

    Idempotency:
        Not idempotent — each CLI invocation appends anew (by design for forensic timelines).

    Raises:
        ``TypeError``, ``ValueError``: JSON serialization faults if ``preview_or_result`` nests non-primitive exotic types.
        ``OSError``: Append failures (permissions, disk full).
    """
    row: dict[str, Any] = {
        "schema_version": 1,
        "audit_id": str(uuid.uuid4()),
        "timestamp_utc": utc_now_iso(),
        "phase": phase,
        "profile_name": name,
        "dry_run": dry_run,
        "detail": preview_or_result,
    }
    path = audit_jsonl(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return row

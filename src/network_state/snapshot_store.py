"""Network State named snapshots (JSONL plus default profile pointer).

Parallels legacy :mod:`~src.proxy_guard.known_good_store` but persists under separate paths
managed by :mod:`paths`. ``proxy-guard --known-good`` consults these rows before falling back
to ``proxy_known_good_snapshots.jsonl``.

Key invariants:
    * **Append-only** JSON lines; lookups scan forward and keep the youngest row per name.
    * ``risk_summary`` reuses Parser risk labels from Proxy Guard snapshots.
    * Hydration relies on ``ProxySnapshot.from_json_dict`` — unknown keys tolerated per model rules.

Malformed data:
    JSON decode failures skipped; partially typed rows discarded during iteration predicates.

Timezone:
    ``saved_at`` is UTC ISO from :func:`~src.core.time_utils.utc_now_iso`.

Audit Notes:
    Pair JSONL deltas with ``network_state_audit.jsonl`` restores when reconciling intentional proxy moves.

Raises:
    :func:`write_default_profile` emits ``ValueError`` for unknown profiles; hydration helpers return
    ``None`` instead of throwing.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..core.time_utils import utc_now_iso
from ..proxy_guard.known_good_store import summarize_snapshot_risk
from ..proxy_guard.models import ProxySnapshot
from .paths import default_profile_json, snapshots_jsonl

SCHEMA_VERSION = 1


def append_snapshot(
    repo_root: Path, *, name: str, snapshot: ProxySnapshot, risk_summary: str | None = None
) -> dict[str, Any]:
    """Serialize and append one capture row for CLI ``network-state snapshot save``.

    Args:
        repo_root: Resolved toolkit root honoring ``--repo-root``.
        name: Operator-visible profile designation.
        snapshot: Canonical capture including WinINET/Git/npm/env/WinHTTP fields.
        risk_summary: Optional override for ``list`` readability.

    Returns:
        Row dictionary mirroring persisted JSON minus trailing newline bookkeeping.

    Side effects:
        Creates ``logs`` as needed and appends UTF-8 JSONL.

    Raises:
        Propagates ``OSError`` on IO failures only.
    """
    path = snapshots_jsonl(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    risk = risk_summary or summarize_snapshot_risk(snapshot)
    row: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "name": name.strip(),
        "saved_at": utc_now_iso(),
        "risk_summary": risk,
        "snapshot": snapshot.to_jsonable(),
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def iter_records(repo_root: Path) -> Iterator[dict[str, Any]]:
    """Yield chronological JSON objects that satisfy minimal schema guards."""
    path = snapshots_jsonl(repo_root)
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("name") and isinstance(obj.get("snapshot"), dict):
                yield obj


def get_latest_named(repo_root: Path, name: str) -> dict[str, Any] | None:
    """Return freshest JSON dict for ``name`` using linear insertion order semantics."""
    want = name.strip()
    last: dict[str, Any] | None = None
    for rec in iter_records(repo_root):
        if str(rec.get("name")) == want:
            last = rec
    return last


def snapshot_from_record(rec: dict[str, Any] | None) -> ProxySnapshot | None:
    """Coerce persisted ``snapshot`` sub-object into immutable dataclass (or ``None``)."""
    if rec is None:
        return None
    snap = rec.get("snapshot")
    if not isinstance(snap, dict):
        return None
    try:
        return ProxySnapshot.from_json_dict(snap)
    except (KeyError, TypeError, ValueError):
        return None


def load_default_record(repo_root: Path) -> dict[str, Any] | None:
    """Load ``network_state_default.json`` when present without raising on malformed files."""
    path = default_profile_json(repo_root)
    if not path.is_file():
        return None
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return blob if isinstance(blob, dict) else None


def write_default_profile(repo_root: Path, *, name: str) -> Path:
    """Overwrite ``network_state_default.json`` with newest JSON row for ``name``.

    Args:
        repo_root: Resolved toolkit checkout root.
        name: Existing profile label referencing JSONL rows.

    Returns:
        Absolute path written.

    Raises:
        ValueError: Unknown profile lacking JSONL backing.

    Side effects:
        Creates ``config`` directory as needed.

    Failure modes:
        Partial writes if the interpreter aborts mid-write warrant deleting the truncated JSON and rerun.
    """

    rec = get_latest_named(repo_root, name)
    if rec is None:
        raise ValueError(f"Unknown profile name: {name}")
    path = default_profile_json(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    out = {
        "schema_version": SCHEMA_VERSION,
        "name": rec.get("name"),
        "saved_at": rec.get("saved_at"),
        "risk_summary": rec.get("risk_summary"),
        "snapshot": rec.get("snapshot"),
    }
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def list_profile_summaries(repo_root: Path) -> list[dict[str, Any]]:
    """Enumerate latest metadata per snapshot name annotated with ``is_default``."""

    by_name: dict[str, dict[str, Any]] = {}
    for rec in iter_records(repo_root):
        by_name[str(rec["name"])] = rec
    default_rec = load_default_record(repo_root)
    default_name = str(default_rec["name"]) if default_rec and default_rec.get("name") else None
    return [
        {
            "name": nm,
            "saved_at": rec.get("saved_at"),
            "risk_summary": rec.get("risk_summary"),
            "is_default": default_name == nm,
        }
        for nm, rec in sorted(by_name.items(), key=lambda x: x[0])
    ]


def resolve_named_snapshot(repo_root: Path, name: str) -> ProxySnapshot | None:
    """Hydrate typed snapshot for ``proxy-guard --known-good`` precedence lookups."""
    return snapshot_from_record(get_latest_named(repo_root, name))



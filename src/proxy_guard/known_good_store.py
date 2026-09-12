"""Append-only named snapshots for legacy ``proxy-snapshot`` tooling.

Writes ``logs/proxy_known_good_snapshots.jsonl`` and optional
``config/last_known_good_proxy.json``. Mirrors the schema used by broader Proxy Guard rollback
utilities but namespaces storage separately from transient ``logs/proxy_snapshots.jsonl`` rollback
captures consumed by ``proxy-rollback``.

Key invariants:
    * **Append-only JSONL**: latest row wins per ``name`` when readers scan sequentially.
    * ``schema_version`` is fixed per module constant; parsers skip malformed JSON lines silently.
    * ``risk_summary`` is derived from typed ``ProxySnapshot`` via parser risk labels (never raw host IDs).

Malformed or duplicate lines:
    Readers ignore JSON decode failures and malformed objects; deterministic tests should write clean payloads.

Timezone:
    ``saved_at`` comes from ``utc_now_iso()`` (timezone-aware UTC string).

Raises:
    :func:`snapshot_from_record` returns ``None`` on conversion failure instead of raising.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..core.time_utils import utc_now_iso
from .models import ProxySnapshot
from .parser import parse_proxy_server, summarize_proxy_risk

SCHEMA_VERSION = 1
SNAPSHOTS_FILENAME = "proxy_known_good_snapshots.jsonl"
DEFAULT_CONFIG_RELPATH = Path("config") / "last_known_good_proxy.json"


def snapshots_jsonl_path(repo_root: Path) -> Path:
    """Return absolute JSONL sink under ``repo_root``."""
    return repo_root / "logs" / SNAPSHOTS_FILENAME


def default_known_good_path(repo_root: Path) -> Path:
    """Return pointer JSON path for optional default profile replication."""
    return repo_root / DEFAULT_CONFIG_RELPATH


def summarize_snapshot_risk(snapshot: ProxySnapshot) -> str:
    """Produce a categorical risk banner for CLI ``list`` output.

    Uses parser heuristics (loopback literals, PAC enablement) independent of attribution.

    Args:
        snapshot: Joined HKCU/Git/npm/env/WinHTTP capture.

    Returns:
        Short human-readable slug (still **configuration-derived**, never a hostname token).
    """
    parsed = parse_proxy_server(snapshot.proxy_server)
    return summarize_proxy_risk(parsed, snapshot.proxy_enable == 1)


def append_named_snapshot(
    repo_root: Path,
    *,
    name: str,
    snapshot: ProxySnapshot,
    risk_summary: str | None = None,
) -> dict[str, Any]:
    """Persist one immutable JSON line for ``name``.

    Args:
        repo_root: Toolkit checkout root.
        name: Operator label (latest row supersedes prior semantics for lookups).
        snapshot: Canonical :class:`~src.proxy_guard.models.ProxySnapshot`.
        risk_summary: Optional override; recomputed automatically when omitted.

    Returns:
        The serialized row dictionary (excluding trailing newline bookkeeping).

    Side effects:
        Creates ``logs`` if missing and appends one UTF-8 JSON line atomically via ``open(..., 'a')``.

    Raises:
        ``OSError`` if disk permissions block append.
    """
    path = snapshots_jsonl_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    risk = risk_summary or summarize_snapshot_risk(snapshot)
    row: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "name": name.strip(),
        "saved_at": utc_now_iso(),
        "risk_summary": risk,
        "snapshot": snapshot.to_jsonable(),
    }
    line = json.dumps(row, ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line)
    return row


def write_default_config(repo_root: Path, record: dict[str, Any]) -> Path:
    """Flatten the latest composite row into a single curated JSON artifact.

    Args:
        repo_root: Toolkit checkout root.
        record: Payload previously returned by :func:`append_named_snapshot`.

    Returns:
        Path written (``config/last_known_good_proxy.json``).

    Side effects:
        Overwrites destination file atomically via ``write_text``.

    Raises:
        ``OSError`` on encoding or permission failures.

    Failures modes:
        Partial JSON corrupts tooling; callers should serialize ``record`` verbatim without mutation.
    """
    path = default_known_good_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    out = {
        "schema_version": SCHEMA_VERSION,
        "name": record.get("name"),
        "saved_at": record.get("saved_at"),
        "risk_summary": record.get("risk_summary"),
        "snapshot": record.get("snapshot"),
    }
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def iter_named_records(repo_root: Path) -> Iterator[dict[str, Any]]:
    """Yield sanitized snapshot rows preserving JSONL insertion order.

    Args:
        repo_root: Repository root locating ``logs/proxy_known_good_snapshots.jsonl``.

    Yields:
        Dict rows containing ``name`` plus nested ``snapshot`` mapping.

    Raises:
        None—IO errors propagate only from ``Path.open``.

    Handling of malformed data:
        Drops blank lines / JSON decode failures / dicts lacking required keys without raising.

    Idempotency:
        Iterator is repeatable but re-reads file each call—no caching layer.
    """
    path = snapshots_jsonl_path(repo_root)
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


def get_latest_named_record(repo_root: Path, name: str) -> dict[str, Any] | None:
    """Return the youngest JSON row for ``name`` based on linear scan ordering.

    Args:
        repo_root: Toolkit checkout root.
        name: Snapshot label trimmed for comparison.

    Returns:
        Parsed dict or ``None`` when absent or file missing.

    Idempotency:
        Function is read-only; concurrent writers may race—callers tolerate eventual consistency.

    Constraints:
        Relies purely on insertion order rather than timestamps for tie-breaking stability.
    """
    want = name.strip()
    last: dict[str, Any] | None = None
    for rec in iter_named_records(repo_root):
        if str(rec.get("name")) == want:
            last = rec
    return last


def snapshot_from_record(rec: dict[str, Any] | None) -> ProxySnapshot | None:
    """Materialize a typed snapshot stored inside a JSON dict.

    Args:
        rec: Optional row dict containing ``snapshot`` mapping.

    Returns:
        Hydrated snapshot or ``None`` when coercion fails.

    Failure modes:
        Legacy rows missing fields fall back via :meth:`ProxySnapshot.from_json_dict` defaults.

    Raises:
        None — conversion failures return ``None`` for operator-friendly CLI ergonomics.
    """
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
    """Load curated default pointer JSON produced by ``--as-default`` flows."""
    path = default_known_good_path(repo_root)
    if not path.is_file():
        return None
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(blob, dict):
        return None
    return blob


def list_snapshot_summaries(repo_root: Path) -> list[dict[str, Any]]:
    """Summarize newest row per snapshot name sorted lexicographically by name.

    Args:
        repo_root: Toolkit checkout root.

    Returns:
        Rows include ``has_default_file`` aligning with ``last_known_good_proxy.json``.
        Missing files or malformed JSON yield an empty iterable from readers, producing an empty list.

    Raises:
        None.
    """
    by_name: dict[str, dict[str, Any]] = {}
    for rec in iter_named_records(repo_root):
        n = str(rec.get("name"))
        by_name[n] = rec
    default_rec = load_default_record(repo_root)
    default_name = str(default_rec["name"]) if default_rec and default_rec.get("name") else None
    out: list[dict[str, Any]] = []
    for nm in sorted(by_name.keys()):
        rec = by_name[nm]
        out.append(
            {
                "name": nm,
                "saved_at": rec.get("saved_at"),
                "risk_summary": rec.get("risk_summary"),
                "has_default_file": default_name == nm,
            },
        )
    return out

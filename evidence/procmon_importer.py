"""Parse Procmon CSV exports for HKCU-proxy-relevant registry writes.

Module responsibility:
    Streams :class:`ProcmonRegistryWrite` structs from textual CSV blobs using stdlib ``csv``
    primitives—never shells out to Procmon itself.

System placement:
    Optional enrichment path beside :mod:`evidence.sysmon_reader`; merges into
    ``build_attribution`` when callers embed CSV excerpts in ``attribution_context`` payloads.

Input assumptions:
    Headers follow Sysinternals defaults (``Operation``, ``Process Name``, ``Path``, ``Detail``) or lowercase analogs exported by tooling.

Output guarantees:
    Iterator yields chronological reader order identical to Procmon-export row order modulo filtered ops.

Duplicates / malformed rows:
    ``csv.DictReader`` skips physical blank lines silently; unrecognized operations drop before yielding.

Raises:
    None—empty ``text`` short-circuit returns without iteration.

Audit Notes:
    Store original CSV shards under operator-controlled archives; ingestion here does not redact credentials automatically—sanitize before staging fixtures.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProcmonRegistryWrite:
    """Single registry mutate row captured by Procmon.

    Attributes:
        process_name: Image field from exporter (may include path).
        operation: Typically ``RegSetValue`` / ``RegDeleteValue``.
        path: Registry path literal.
        detail: Detail column blobs (often contains datum payload).
    """

    process_name: str
    operation: str
    path: str
    detail: str = ""


REGISTRY_OPS = frozenset({"RegSetValue", "RegDeleteValue"})


def iter_procmon_registry_writes_from_csv(text: str) -> Iterator[ProcmonRegistryWrite]:
    """Yield registry-operation rows constrained to REGISTRY_OPS.

    Args:
        text: Full CSV UTF-8 string (Procmon “Save…” output).

    Yields:
        :class:`ProcmonRegistryWrite` for each qualifying line with nonempty path/detail pair.

    Idempotency:
        Pure iterator over provided string—calling twice requires separate ``text`` copies.

    Constraints:
        Non-registry operations skipped entirely—even if correlate via later heuristics.
    """

    if not text.strip():
        return
    reader = csv.DictReader(io.StringIO(text))
    for raw in reader:
        op = str(raw.get("Operation") or raw.get("operation") or "").strip()
        if op and op not in REGISTRY_OPS:
            continue
        proc = str(raw.get("Process Name") or raw.get("ProcessName") or raw.get("process") or "")
        path = str(raw.get("Path") or raw.get("path") or "")
        det = str(raw.get("Detail") or raw.get("detail") or "")
        if path or det:
            yield ProcmonRegistryWrite(
                process_name=proc, operation=op or "RegSetValue", path=path, detail=det
            )


def procmon_concerns_proxy(row: ProcmonRegistryWrite) -> bool:
    """Return True when concatenated registry path/details mention proxy hotspots.

    Args:
        row: Parsed CSV tuple.

    Returns:
        Boolean keyword scan over ``internet settings`` or ``proxy`` tokens (case-folded).

    Known failure modes:
        Misses alternate languages or encoded binary blobs lacking ASCII keywords—escalate to manual review when uncertain.
    """

    pl = (row.path + " " + row.detail).lower()
    return "proxy" in pl or "internet settings" in pl


def procmon_row_to_dict(row: ProcmonRegistryWrite) -> dict[str, Any]:
    """Project frozen dataclass back into canonical Procmon-ish column dictionary.

    Purpose:
        Simplifies JSON fixtures mirroring exporter header spellings without duplicating serializers.

    Returns:
        Shallow mapping with PascalCase-ish keys aligning to default CSV headings.
    """

    return {
        "Process Name": row.process_name,
        "Operation": row.operation,
        "Path": row.path,
        "Detail": row.detail,
    }

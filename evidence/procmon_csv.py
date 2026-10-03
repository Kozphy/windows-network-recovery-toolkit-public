"""Procmon CSV → structured registry-write rows — thin facade over :mod:`evidence.procmon_importer`.

Module responsibility:
    Re-export iterator + predicates so portfolio narratives refer to ``evidence.procmon_csv`` without importing the
    heavier importer module path directly.

System placement:
    Optional ingest stage before :func:`~evidence.attribution_engine.build_attribution` consumes ``ProcmonRegistryWrite`` rows.

Input assumptions:
    CSV text follows Sysinternals Procmon export columns documented in :mod:`evidence.procmon_importer`.

Output guarantees:
    Iterator yields immutable frozen dataclass tuples in file order modulo filtered operations.

Side effects:
    None—pure parsing over in-memory strings.

Audit Notes:
    Operators must archive authoritative CSV exports separately—this parser does not verify digital signatures on exports.
"""

from __future__ import annotations

from evidence.procmon_importer import (
    ProcmonRegistryWrite,
    iter_procmon_registry_writes_from_csv,
    procmon_concerns_proxy,
)

__all__ = [
    "ProcmonRegistryWrite",
    "iter_procmon_registry_writes_from_csv",
    "procmon_concerns_proxy",
]

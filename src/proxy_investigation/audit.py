"""Append-only JSONL audit for proxy investigations.

Module responsibility:
    Persist one JSON-serializable investigation row per run under ``logs/proxy_investigation.jsonl``.

System placement:
    Optional tail called from ``workflow`` when ``write_audit=True``.

Output guarantees:
    Each append is a single JSONL line via ``core.jsonl.append_jsonl`` (append-only).

Side effects:
    Creates parent directories as needed; writes local disk.

Idempotency:
    Not idempotent — each investigation appends a new line.

Audit Notes:
    * ``human_report_excerpt`` truncates markdown to 2000 chars for log size control.
    * Correlate ``run_id`` with ``reports/proxy_investigations/<run_id>.md`` when present.
"""

from __future__ import annotations

from pathlib import Path

from ..core.jsonl import append_jsonl as append_jsonl_core
from .constants import AUDIT_JSONL
from .models import ProxyInvestigationResult


def audit_path(repo_root: Path) -> Path:
    """Resolve the investigation audit JSONL path under the repository root."""
    return repo_root / AUDIT_JSONL


def append_investigation(result: ProxyInvestigationResult, *, repo_root: Path) -> Path:
    """Append one investigation record to the audit JSONL file.

    Args:
        result: Investigation run to serialize.
        repo_root: Toolkit root containing ``logs/``.

    Returns:
        Path to the JSONL file written.

    Side effects:
        Appends one line to ``logs/proxy_investigation.jsonl``.
    """
    path = audit_path(repo_root)
    payload = result.to_jsonable()
    payload["human_report_excerpt"] = result.human_report[:2000]
    append_jsonl_core(path, payload)
    return path

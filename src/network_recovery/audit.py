"""Append-only audit sink for network recovery scenario runs.

Module responsibility:
    Resolve audit path and append ``DiagnosisResult`` payloads to JSONL.

System placement:
    Called after diagnose/remediate/auto_fix; delegates to ``src.logging.audit.append_jsonl``.

Key invariants:
    * Append-only ``logs/network_recovery_events.jsonl`` under repo root.
    * One row per diagnosis/remediation invocation.

Side effects:
    Creates ``logs/`` directory if missing; appends one JSON object per line.

Audit Notes:
    * Primary evidence trail for network recovery scenario runs.
    * Recovery: replay from JSONL; no built-in tamper chain in this module.
"""

from __future__ import annotations

from pathlib import Path

from ..logging.audit import append_jsonl
from .models import AuditRecord, DiagnosisResult


def network_recovery_audit_path(repo_root: Path) -> Path:
    """Network recovery audit path.
    
    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.
    
    Returns:
        The Path result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    return repo_root / "logs" / "network_recovery_events.jsonl"


def append_network_recovery_audit(repo_root: Path, result: DiagnosisResult) -> Path:
    """Append one diagnosis row; returns the log path.

    Args:
        repo_root: Repository root containing ``logs/``.
        result: Completed diagnosis including optional remediation_executed.

    Returns:
        Path to ``logs/network_recovery_events.jsonl``.

    Side effects:
        Appends one JSONL record via ``append_jsonl``.
    """
    path = network_recovery_audit_path(repo_root)
    append_jsonl(path, AuditRecord.from_diagnosis(result).payload)
    return path

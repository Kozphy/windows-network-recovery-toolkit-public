"""Audit, replay, and report exports for the windows_network_toolkit package.

Module responsibility:
    Re-exports the canonical audit entry points: append-only JSONL logging,
    tail reads, fixture replay through the incident pipeline, and audit-ready
    report generation.

System placement:
    Consumed by the ``audit`` CLI command group and by operator scripts that
    need to record, inspect, or replay toolkit decisions.  The underlying
    JSONL logger writes to ``logs/erp_decision_audit.jsonl`` by default.

Key invariants:
    ``append_audit`` is append-only; existing records are never overwritten.
    ``replay_jsonl`` is read-only with respect to the fixture file — it may
    write new audit records via the pipeline's standard audit path.

Side effects:
    ``append_audit``: writes to the JSONL audit log file.
    ``read_audit_tail``, ``replay_jsonl``, ``generate_report``: read-only
    (no file writes at the package level).
"""

from .jsonl_logger import append_audit, read_audit_tail
from .replay import replay_jsonl
from .report_generator import generate_report

__all__ = ["append_audit", "generate_report", "read_audit_tail", "replay_jsonl"]

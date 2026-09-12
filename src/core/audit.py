"""DEPRECATED: use ``src.platform.audit``."""

from __future__ import annotations

from src.platform.audit import (
    DEFAULT_AUDIT_PATH,
    AuditRecord,
    append_audit,
    audit_pipeline_step,
    read_audit_tail,
)

# backward-compatible alias
audit_from_pipeline = audit_pipeline_step

__all__ = [
    "DEFAULT_AUDIT_PATH",
    "AuditRecord",
    "append_audit",
    "audit_from_pipeline",
    "audit_pipeline_step",
    "read_audit_tail",
]

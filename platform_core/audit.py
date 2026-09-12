"""Append-only platform audit rows bridging operator actions to ``audit.jsonl``.

This module is the narrow façade over :func:`platform_core.storage.record_audit` for callers
that already have string metadata (actor, action, decision) and want a persisted
:class:`~platform_core.models.PlatformAuditRecord` instance back for API responses.
"""

from __future__ import annotations

import uuid

from .models import PlatformAuditRecord, utc_now_iso
from .storage import record_audit


def write_audit(
    *,
    actor: str,
    action: str,
    target_type: str = "",
    target_id: str = "",
    decision: str = "",
    rationale: str = "",
) -> PlatformAuditRecord:
    """Materialize one audit record, append it as JSONL, and return the hydrated model.

    Purpose:
        Guarantee every manual or API-gated platform mutation has a matching append-only row
        suitable for ``GET /platform/audit`` style review (when RBAC permits).

    Args:
        actor: Stable operator or service identifier (never a raw secret).
        action: Verb phrase such as ``remediation_preview`` or ``remediation_execute``.
        target_type: Optional entity class (``failure_event``, ``endpoint``, etc.).
        target_id: Optional stable id for correlation.
        decision: Normalized outcome token (for example ``allowed``, ``blocked``).
        rationale: Human-readable justification string for auditors.

    Returns:
        The :class:`~platform_core.models.PlatformAuditRecord` written to disk (includes fresh
        ``audit_id`` and RFC3339-style ``timestamp`` from :func:`~platform_core.models.utc_now_iso`).

    Raises:
        OSError / PermissionError may propagate from :mod:`platform_core.storage` if the JSONL root
        is not writable.

    Side effects:
        Appends exactly one serialized JSON object to ``platform_data/audit.jsonl`` (or
        equivalent under ``PLATFORM_DATA_DIR``).

    Idempotency:
        Not idempotent — each invocation allocates a **new** ``audit_id``. Callers must not infer
        deduplication beyond their own retries.

    Engineering Notes:
        Payload validation is intentionally light; FastAPI routers should normalize ``actor`` and
        ``action`` enums if stricter auditing becomes necessary.

    Audit Notes:
        If rows stop appearing despite 200 responses, verify filesystem quotas and concurrent
        writers corrupting trailing JSON — ``iter_jsonl`` skips malformed lines but gaps in
        sequence numbers may indicate partial writes.
    """
    rec = PlatformAuditRecord(
        audit_id=str(uuid.uuid4()),
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        decision=decision,
        rationale=rationale,
        timestamp=utc_now_iso(),
    )
    record_audit(rec.model_dump())
    return rec

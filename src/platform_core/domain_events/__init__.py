"""Versioned domain event kernel — one envelope, one writer, one verifier.

This package is the Level-1 production-readiness vertical slice:
canonical JSONL under ``.audit/canonical_custody.jsonl`` (or ``WNT_AUDIT_DIR``).

Legacy ``erp.audit.v1`` rows remain verifiable via the compat adapter.
"""

from __future__ import annotations

from src.platform_core.domain_events.compat import (
    is_legacy_audit_record,
    legacy_record_as_envelope_view,
)
from src.platform_core.domain_events.envelope import (
    DOMAIN_EVENT_SCHEMA,
    SUPPORTED_SCHEMA_VERSIONS,
    build_envelope,
    validate_envelope,
)
from src.platform_core.domain_events.verify import verify_domain_stream
from src.platform_core.domain_events.writer import append_domain_event

__all__ = [
    "DOMAIN_EVENT_SCHEMA",
    "SUPPORTED_SCHEMA_VERSIONS",
    "append_domain_event",
    "build_envelope",
    "is_legacy_audit_record",
    "legacy_record_as_envelope_view",
    "validate_envelope",
    "verify_domain_stream",
]

"""Endpoint Reliability Platform core — typed models, policy gates, privacy redaction, JSONL I/O.

Module responsibility:
    Provides the **domain layer** for the optional local prototype: heartbeat/snapshot/failure
    events, remediation previews/executions, RBAC helpers, and remediation registry integration.
    Files on disk under ``platform_data/*.jsonl`` (or ``PLATFORM_DATA_DIR``) are the system of
    record for demos.

System placement:
    ``backend/platform_routes.py`` and ``endpoint_agent/*`` import this package. The beginner
    ``scripts/*.bat`` path does not require it.

Key invariants:
    * Storage is **append-only JSONL** unless an operator edits files manually—readers must skip
      malformed tail lines after crashes.
    * High-risk remediation paths are **blocked or manual-only** via ``platform_core.policy`` and
      ``platform_core.remediation_registry``.
    * Payloads crossing HTTP should pass through ``platform_core.privacy`` where redaction applies.

Input assumptions:
    Callers supply dicts or Pydantic models matching contracts in ``models.py`` and
    ``schemas.py``; this package does not silently coerce unknown fields beyond Pydantic defaults.

Output guarantees:
    Public APIs return models or plain dicts suitable for FastAPI ``json`` responses when
    documented as such.

Side effects:
    Any ``append_*`` or ``record_*`` helper may create directories and append bytes to JSONL.

Audit Notes:
    Review ``platform_data/audit.jsonl`` alongside ``remediation_executions.jsonl`` after any
    demo ``POST /platform/remediation/execute`` — blocked rows should include rationale fields
    from policy evaluation.
"""

from .models import (
    EndpointIdentity,
    EndpointSnapshot,
    FailureEvent,
    PlatformAuditRecord,
    RemediationExecution,
    RemediationPolicy,
    RemediationPreview,
)
from .reasoning_models import (
    EndpointEvent,
    EvidenceTree,
    Observation,
    PolicyDecision,
    ProofResult,
    ReasoningRun,
    ReliabilityImpact,
    StateTransition,
)

__all__ = [
    "EndpointIdentity",
    "EndpointSnapshot",
    "FailureEvent",
    "RemediationPolicy",
    "RemediationPreview",
    "RemediationExecution",
    "PlatformAuditRecord",
    "Observation",
    "EndpointEvent",
    "StateTransition",
    "EvidenceTree",
    "ProofResult",
    "ReliabilityImpact",
    "PolicyDecision",
    "ReasoningRun",
]

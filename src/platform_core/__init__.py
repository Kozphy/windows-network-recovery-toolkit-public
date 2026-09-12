"""Platform core for Technology Risk & Control Analytics on Windows endpoints.

Module responsibility:
    Provides the authoritative schema version constants and the package namespace
    for all platform_core sub-packages: classification, proof, policy, decision,
    governance, audit, evidence, and controls.

System placement:
    Root package of ``src/platform_core/``.  Imported transitively by every
    sub-module that requires schema version alignment.  Downstream callers
    (``src/cli.py``, ``backend/``, and the ``windows_network_toolkit`` CLI) consume
    these constants to stamp structured JSON outputs and audit records.

Key invariants:
    ``SCHEMA_VERSION`` and ``AUDIT_SCHEMA_VERSION`` are immutable string constants
    for the lifetime of a process.  No runtime state is stored here.

Side effects:
    None.

Failure modes:
    Import errors propagate to every consumer; no fallback mechanism is provided.
"""

from __future__ import annotations

SCHEMA_VERSION = "erp.platform.v1"
AUDIT_SCHEMA_VERSION = "erp.audit.v1"

__all__ = ["AUDIT_SCHEMA_VERSION", "SCHEMA_VERSION"]

"""Project rich registry-writer telemetry into the strict ``registry_writer_proof`` contract.

This thin facade wraps :mod:`evidence.registry_writer` to emit exactly the dashboard- and
API-friendly shape requested by the proxy remediation contract:

``{"registry_writer_proof": {"status": "unavailable" | "found", ...}}``

It never installs Sysmon, never elevates privileges, never clears event logs, and never kills
processes. Permission errors and missing telemetry collapse into a clear ``unavailable`` shape
with a stable ``limitation`` field rather than a stack trace.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from evidence.registry_writer import (
    WRITER_PROOF_UNAVAILABLE,
    RegistryWriterEvidence,
    collect_registry_writer_evidence,
)

LISTENER_LIMITATION = (
    "listener/process correlation does not prove registry writer identity; this proof requires "
    "Sysmon Event ID 13, Security Event ID 4657 with registry auditing, or imported Procmon CSV."
)


def _evidence_event_dict(evidence: RegistryWriterEvidence) -> dict[str, Any]:
    """Project a :class:`RegistryWriterEvidence` into the public event payload."""

    return {
        "timestamp": evidence.timestamp,
        "image": evidence.process_image,
        "process_id": evidence.process_id,
        "user": evidence.user,
        "target_object": evidence.target_object,
        "value_name": evidence.value_name,
        "details": evidence.current_value,
        "event_source": evidence.event_source,
        "source_event_id": evidence.source_event_id,
        "confidence": evidence.confidence,
    }


def _unavailable_payload(
    reason: str, *, sysmon_status: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build the canonical unavailable response."""

    return {
        "registry_writer_proof": {
            "status": "unavailable",
            "evidence_level": "observation",
            "reason": reason,
            "events": [],
            "limitation": LISTENER_LIMITATION,
            "sysmon_status": sysmon_status or {},
        }
    }


def _found_payload(
    events: list[dict[str, Any]], *, sysmon_status: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Build the canonical found response."""

    return {
        "registry_writer_proof": {
            "status": "found",
            "evidence_level": "proof_candidate",
            "events": events,
            "limitation": (
                "Event log supports writer attribution but the operator should still review the row, "
                "preserve the trace, and verify process identity against signing/parent context."
            ),
            "sysmon_status": sysmon_status or {},
        }
    }


def build_registry_writer_proof(
    *,
    since_seconds: int = 120,
    procmon_csv_path: str | Path | None = None,
    include_security_log: bool = True,
    run: Callable[..., Any] = subprocess.run,
    platform_name: str | None = None,
) -> dict[str, Any]:
    """Run the registry-writer evidence collectors and project the strict contract.

    Args:
        since_seconds: Lookback window in seconds for live event-log queries.
        procmon_csv_path: Optional operator-supplied Procmon CSV export.
        include_security_log: When ``True``, also query Security Event ID 4657.
        run: Subprocess runner injected by tests.
        platform_name: Optional platform override for testability.

    Returns:
        Mapping ``{"registry_writer_proof": {...}}`` matching the documented contract.
    """

    try:
        bundle = collect_registry_writer_evidence(
            since_seconds=since_seconds,
            procmon_csv_path=procmon_csv_path,
            include_security_log=include_security_log,
            run=run,
            platform_name=platform_name,
        )
    except PermissionError as exc:
        return _unavailable_payload(f"permission_denied:{exc}")
    except OSError as exc:
        return _unavailable_payload(f"os_error:{type(exc).__name__}:{exc}")

    evidence: list[RegistryWriterEvidence] = list(bundle.get("evidence") or [])
    sysmon_status = bundle.get("sysmon_status") or {}
    if not evidence:
        reason = WRITER_PROOF_UNAVAILABLE
        for limitation in bundle.get("limitations") or []:
            text = str(limitation)
            if not text:
                continue
            if "no sysmon event" in text.lower() or "writer proof unavailable" in text.lower():
                reason = text
                break
        return _unavailable_payload(reason, sysmon_status=sysmon_status)

    events = [_evidence_event_dict(item) for item in evidence]
    return _found_payload(events, sysmon_status=sysmon_status)

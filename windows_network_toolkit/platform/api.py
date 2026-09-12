"""FastAPI router providing the canonical Endpoint Reliability Platform (ERP) HTTP API.

Module responsibility:
    Define all ERP platform routes, grouped under the ``"erp-platform"`` tag.
    Accepts raw signals or fixture paths, runs the incident pipeline, stores
    the latest result in the in-memory session store, and returns structured
    JSON responses.

System placement:
    Mounted into the main FastAPI application (``backend.main`` or
    ``windows_network_toolkit`` app entry point) via ``include_router``.
    Delegates all business logic to ``pipeline.run_incident_pipeline``,
    ``audit.replay.replay_jsonl``, and the ``store`` module.

Key invariants:
    * All routes that touch remediation return ``dry_run=True`` in their
      response by default; live execution is explicitly blocked in
      ``/platform/remediation/confirm`` unless the full platform_core
      remediation execute path is used with admin + typed phrase.
    * The remediation confirm endpoint is a safe-mode alias: it never
      executes destructive actions directly.  It echoes a preview only.
    * Fixture file resolution searches the repo-relative ``examples/``
      directory as a fallback when the provided path is not an absolute file.

Side effects:
    * ``set_latest(result)`` on ``/platform/diagnose`` and ``/platform/replay``
      updates the in-memory session store (process-local; not persisted).

Failure modes:
    * ``404`` — fixture path not found.
    * Upstream pipeline exceptions propagate as unhandled 500 errors;
      callers should handle these via standard FastAPI error middleware.

Audit Notes:
    The ``/platform/audit/logs`` endpoint exposes a tail of the hash-chained
    audit JSONL.  Correlate ``audit_id`` fields with spool and pipeline records
    to trace a decision end-to-end.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException

from windows_network_toolkit import SERVICE_NAME, __version__
from windows_network_toolkit.audit.jsonl_logger import read_audit_tail
from windows_network_toolkit.audit.replay import _incident_type_value
from windows_network_toolkit.pipeline import run_incident_pipeline
from windows_network_toolkit.platform.schemas import (
    DiagnoseRequest,
    HealthResponse,
    RemediationConfirmRequest,
    ReplayRequest,
    StatusResponse,
)
from windows_network_toolkit.platform.store import get_latest, get_timeline, set_latest
from windows_network_toolkit.remediation import preview_proxy_disable  # used by confirm

router = APIRouter(tags=["erp-platform"])

_REPO = Path(__file__).resolve().parents[2]


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Return service liveness status.

    Returns:
        ``HealthResponse`` with ``status="ok"``, service name, and version.
    """
    return HealthResponse(status="ok", service=SERVICE_NAME, version=__version__)


@router.get("/platform/status", response_model=StatusResponse)
def platform_status() -> StatusResponse:
    """Return platform operating mode and safe-mode flags.

    Returns:
        ``StatusResponse`` indicating ``platform_mode="local_replay"``,
        ``safe_mode=True``, and ``remediation_default="dry_run"``.
    """
    return StatusResponse()


@router.post("/platform/diagnose")
def platform_diagnose(body: DiagnoseRequest) -> dict[str, Any]:
    """Run the incident pipeline against supplied signals or a fixture file.

    When ``fixture_path`` is provided, the file is resolved relative to the
    repo ``examples/`` directory as a fallback.  Results are stored in the
    in-memory session store so ``/platform/decision/latest`` reflects them.

    Args:
        body: ``DiagnoseRequest`` containing optional ``signals``,
            ``fixture_path``, ``incident_id``, and ``dry_run`` flag.

    Returns:
        Dict with ``incident_id``, ``timeline``, ``decision``, ``policy``,
        ``remediation``, ``dry_run``, and ``version``.

    Raises:
        HTTPException(404): Fixture file not found at the given path or in the
            ``examples/`` fallback directory.
    """
    if body.fixture_path:
        path = Path(body.fixture_path)
        if not path.is_file():
            path = _REPO / "windows_network_toolkit" / "examples" / body.fixture_path
        if not path.is_file():
            raise HTTPException(status_code=404, detail=f"fixture not found: {body.fixture_path}")
        result = run_incident_pipeline(
            jsonl_path=path, incident_id=body.incident_id, dry_run=body.dry_run
        )
    else:
        result = run_incident_pipeline(
            signals=body.signals, incident_id=body.incident_id, dry_run=body.dry_run
        )
    set_latest(result)
    return {
        "incident_id": result.bundle.incident_id,
        "timeline": result.timeline,
        "decision": result.decision.model_dump(),
        "policy": result.policy,
        "remediation": result.remediation,
        "dry_run": body.dry_run,
        "version": __version__,
    }


@router.get("/platform/evidence/timeline")
def platform_evidence_timeline() -> dict[str, Any]:
    """Return the timeline from the most recently stored pipeline result.

    Read-only; always returns ``dry_run=True`` to signal safe-mode context.

    Returns:
        Dict with ``timeline`` (list of event dicts), ``count``, and
        ``dry_run=True``.
    """
    timeline = get_timeline()
    return {"timeline": timeline, "count": len(timeline), "dry_run": True}


@router.get("/platform/decision/latest")
def platform_decision_latest() -> dict[str, Any]:
    """Return the latest decision from the in-memory session store.

    Returns ``decision=None`` with a guidance message when no pipeline run has
    been executed in the current process lifetime.

    Returns:
        Dict with ``decision`` (or ``None``), ``incident_id`` (or absent),
        and ``dry_run=True``.
    """
    latest = get_latest()
    if not latest:
        return {
            "decision": None,
            "message": "No diagnosis run yet. POST /platform/diagnose or /platform/replay first.",
            "dry_run": True,
        }
    return {
        "decision": latest.get("decision"),
        "incident_id": latest.get("incident_id"),
        "dry_run": True,
    }


@router.get("/platform/audit/logs")
def platform_audit_logs(limit: int = 50) -> dict[str, Any]:
    """Return a tail of the hash-chained audit JSONL.

    Args:
        limit: Maximum number of records to return (default 50).

    Returns:
        Dict with ``logs`` (list of audit record dicts) and ``count``.
    """
    rows = read_audit_tail(limit=limit)
    return {"logs": rows, "count": len(rows)}


@router.post("/platform/replay")
def platform_replay(body: ReplayRequest) -> dict[str, Any]:
    """Replay an audit JSONL fixture or a signal dict through the pipeline.

    When ``fixture_path`` is provided, the fixture is replayed via
    ``audit.replay.replay_jsonl``; otherwise the signal dict is evaluated
    directly.  Results are stored in the session store.

    Args:
        body: ``ReplayRequest`` with optional ``fixture_path``, ``signals``,
            and ``dry_run`` flag.

    Returns:
        Dict with ``incident_id``, ``timeline``, ``incident_type``,
        ``confidence``, ``decision``, ``policy``, ``remediation``, ``audit``,
        ``dry_run``, and ``version``.

    Raises:
        HTTPException(404): Fixture file not found.
    """
    if body.fixture_path:
        path = Path(body.fixture_path)
        if not path.is_file():
            path = _REPO / "windows_network_toolkit" / "examples" / body.fixture_path
        if not path.is_file():
            raise HTTPException(status_code=404, detail=f"fixture not found: {body.fixture_path}")
        from windows_network_toolkit.audit.replay import replay_jsonl

        result = replay_jsonl(path, dry_run=body.dry_run)
        set_latest(result)
        payload = {
            "incident_id": result.bundle.incident_id,
            "timeline": result.timeline,
            "incident_type": _incident_type_value(result.decision),
            "confidence": result.decision.confidence,
            "decision": result.decision.model_dump(),
            "policy": result.policy,
            "remediation": result.remediation,
            "audit": result.audit_record,
        }
    else:
        result = run_incident_pipeline(signals=body.signals, dry_run=body.dry_run)
        set_latest(result)
        payload = {
            "incident_id": result.bundle.incident_id,
            "timeline": result.timeline,
            "incident_type": _incident_type_value(result.decision),
            "confidence": result.decision.confidence,
            "decision": result.decision.model_dump(),
            "policy": result.policy,
            "remediation": result.remediation,
            "audit": result.audit_record,
        }
    return {**payload, "dry_run": body.dry_run, "version": __version__}


@router.post("/platform/remediation/confirm")
def platform_remediation_confirm(body: RemediationConfirmRequest) -> dict[str, Any]:
    """Safe-mode remediation confirmation endpoint.

    This endpoint is a policy-gated alias: when ``dry_run=True`` it returns a
    preview only.  When ``dry_run=False`` it still returns ``"blocked"``
    because live execution requires the ``platform_core`` remediation execute
    path with admin privileges and a typed confirmation phrase — not this
    endpoint.

    Args:
        body: ``RemediationConfirmRequest`` with ``preview_id``,
            ``confirmation_phrase``, and ``dry_run`` flag.

    Returns:
        Dict with ``result`` (``"preview_only"`` or ``"blocked"``), preview
        data (when in dry-run mode), ``confirmation_required=True``, and
        ``dry_run=True``.
    """
    # Alias semantics: confirm maps to execute-with-guards; always dry_run unless explicitly disabled
    if body.dry_run:
        preview = preview_proxy_disable(dry_run=True)
        return {
            "result": "preview_only",
            "preview": preview,
            "preview_id": body.preview_id or "erp-preview",
            "confirmation_required": True,
            "dry_run": True,
            "message": "Live execution blocked in safe mode. Use platform_core remediation execute with typed phrase.",
        }
    return {
        "result": "blocked",
        "dry_run": True,
        "message": "Destructive execution requires platform_core remediation execute path with admin + confirmation.",
    }

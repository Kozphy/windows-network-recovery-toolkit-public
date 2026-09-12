"""Pydantic request and response schemas for the ERP platform HTTP API.

Module responsibility:
    Define the typed Pydantic models used as FastAPI request bodies and
    response models for all ``/platform/*`` and ``/health`` routes.

System placement:
    Imported by ``platform.api`` (route handlers) and by any client code that
    needs to construct or validate API payloads programmatically.

Key invariants:
    * ``dry_run=True`` is the default on all request schemas that carry a
      ``dry_run`` field, enforcing the platform's preview-first posture.
    * ``safe_mode=True`` and ``remediation_default="dry_run"`` are fixed on
      ``StatusResponse`` — these values must not be toggled by feature flags
      without a corresponding policy review.

Side effects:
    None — pure schema definitions with no I/O.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from windows_network_toolkit import SERVICE_NAME, __version__


class HealthResponse(BaseModel):
    """Response model for ``GET /health``.

    Attributes:
        status: Liveness status string; always ``"ok"`` when the service is
            running.
        service: Service name constant from ``windows_network_toolkit``.
        version: Package version string.
        dry_run_default: Always ``True``; signals that remediation defaults to
            preview mode.
    """

    status: str = "ok"
    service: str = SERVICE_NAME
    version: str = __version__
    dry_run_default: bool = True


class StatusResponse(BaseModel):
    """Response model for ``GET /platform/status``.

    Attributes:
        status: Platform status; always ``"ok"`` when the service is running.
        service: Service name constant.
        version: Package version string.
        platform_mode: Operating mode; ``"local_replay"`` for the current
            single-host replay configuration.
        safe_mode: Always ``True``; reflects the platform's safe-mode posture.
        remediation_default: Always ``"dry_run"``; all remediation is
            preview-only unless explicitly confirmed through the execute path.
    """

    status: str = "ok"
    service: str = SERVICE_NAME
    version: str = __version__
    platform_mode: str = "local_replay"
    safe_mode: bool = True
    remediation_default: str = "dry_run"


class DiagnoseRequest(BaseModel):
    """Request body for ``POST /platform/diagnose``.

    Attributes:
        signals: Flat signal dict to evaluate; may be empty when
            ``fixture_path`` is provided.
        fixture_path: Optional path to a JSONL fixture file.  Resolved
            relative to the repo ``examples/`` directory when not an absolute
            path.
        incident_id: Optional caller-supplied incident identifier; a UUID-
            based ID is generated when omitted.
        dry_run: Preview-only mode flag; defaults to ``True``.
    """

    signals: dict[str, Any] = Field(default_factory=dict)
    fixture_path: str | None = None
    incident_id: str | None = None
    dry_run: bool = True


class ReplayRequest(BaseModel):
    """Request body for ``POST /platform/replay``.

    Attributes:
        fixture_path: Optional JSONL fixture path to replay.  When provided,
            ``audit.replay.replay_jsonl`` is used; otherwise the ``signals``
            dict is evaluated directly.
        signals: Flat signal dict; used when ``fixture_path`` is absent.
        dry_run: Preview-only mode flag; defaults to ``True``.
    """

    fixture_path: str | None = None
    signals: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True


class RemediationConfirmRequest(BaseModel):
    """Request body for ``POST /platform/remediation/confirm``.

    This endpoint is a safe-mode alias; live execution is always blocked here.
    See the ``platform_core`` remediation execute path for destructive actions.

    Attributes:
        preview_id: Optional identifier of the preview to confirm.
        confirmation_phrase: Typed confirmation phrase from the operator.
        dry_run: Preview-only mode flag; defaults to ``True``.  Even when
            ``False``, the confirm endpoint returns ``"blocked"`` — live
            execution requires a separate admin path.
    """

    preview_id: str = ""
    confirmation_phrase: str = ""
    dry_run: bool = True

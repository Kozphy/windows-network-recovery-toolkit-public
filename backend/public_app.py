"""Fixture-mode read-only FastAPI app for the public mirror demo.

Module responsibility:
    Mount health, platform, and technology-risk (trisk) routes suitable for
    local portfolio demos under ``PLATFORM_FIXTURE_MODE=1``. Excludes Stripe
    billing, fleet write surfaces, and enterprise decision-intelligence writes.

System placement:
    Public CLI/demo mirror entry: ``uvicorn backend.public_app:app``.
    Private monorepo may still use ``backend.main:app`` for the full surface.

Key invariants:
    * Fixture/demo mode preferred; remediation remains policy-gated elsewhere.
    * No billing webhook or checkout routes.
    * Loopback-oriented CORS defaults for the Next.js frontend.

Side effects:
    May read fixtures and local JSONL under configured data dirs; does not
    silently mutate Windows registry or firewall.

Failure modes:
    Missing optional routers are skipped with import guards.

Audit Notes:
    Prefer this app for public demos. Detection: OpenAPI tag list lacks billing.
    Recovery: switch to ``backend.main:app`` only inside the private monorepo.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response

logger = logging.getLogger(__name__)

os.environ.setdefault("PLATFORM_FIXTURE_MODE", "1")

_REPO_ROOT = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="Windows Network Recovery Toolkit (public demo)",
    description=(
        "Read-only / fixture-mode demo API. "
        "Observation != proof · correlation != causation · policy ALLOW != safety guarantee."
    ),
    version="0.2.0",
    openapi_tags=[
        {"name": "health", "description": "Liveness"},
        {"name": "platform", "description": "Platform health and fixture reads"},
        {
            "name": "technology-risk-analytics",
            "description": "Read-only incidents, risks, controls, executive reports",
        },
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Redirect browsers to OpenAPI docs."""
    return RedirectResponse(url="/docs")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    """Avoid noisy favicon 404s on the API host."""
    return Response(status_code=204)


@app.get("/health", tags=["health"])
def root_health() -> dict[str, str]:
    """Root liveness probe for the public demo app."""
    try:
        from windows_network_toolkit import SERVICE_NAME, __version__
        from windows_network_toolkit.safety import is_demo_mode
    except ImportError:  # pragma: no cover
        return {
            "status": "ok",
            "service": "windows-network-recovery-toolkit-public",
            "version": "0.2.0",
            "mode": "fixture",
        }
    return {
        "status": "ok",
        "service": SERVICE_NAME,
        "version": __version__,
        "mode": "demo" if is_demo_mode() else "fixture",
        "edition": "public",
    }


def _mount_optional_routers() -> None:
    """Attach read-only / fixture routers when importable."""
    try:
        from backend.platform_routes import router as platform_router

        app.include_router(platform_router)
    except ImportError as exc:  # pragma: no cover
        logger.warning("platform_routes not mounted: %s", exc)

    try:
        from backend.live_observability import router as toolkit_obs_router

        app.include_router(toolkit_obs_router)
    except ImportError as exc:  # pragma: no cover
        logger.warning("live_observability not mounted: %s", exc)

    try:
        from backend.technology_risk_routes import router as technology_risk_router

        app.include_router(technology_risk_router)
    except ImportError as exc:  # pragma: no cover
        logger.warning("technology_risk_routes not mounted: %s", exc)

    try:
        from windows_network_toolkit.platform.api import router as erp_platform_router

        app.include_router(erp_platform_router)
    except ImportError as exc:  # pragma: no cover
        logger.warning("ERP platform router not mounted: %s", exc)


_mount_optional_routers()

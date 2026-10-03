"""FastAPI host bundling SaaS-demo routes, toolkit observability routers, and ``/platform/*``.

Module responsibility:
    Wires JWT-aware diagnosis/monitor/billing surfaces with optional SQLite persistence alongside
    ``live_observability`` helpers and ``platform_routes.router`` (`/platform/...`). Not required to
    run ``python -m src`` or ``failure_system`` CLIs standalone.

System placement:
    Next.js dashboards and scripted clients call localhost instances started via ``uvicorn
    backend.main:app``. ``endpoint_agent`` POSTs sanitized payloads here when operators opt in.

Key invariants:
    * User-scoped access flows through ``get_current_user`` for SaaS-ish endpoints.
    * Diagnosis ingestion paths honor plan quotas via ``backend.legacy_sqlite.try_increment_usage_with_limit``.
    * Billing webhook duplication is tolerated idempotently (see `/webhook` handler docstrings).
    * Platform JSONL ingestion remains orthogonal to SQLite — mixed deployments still separate state.

Failure modes:
    Misconfigured JWT secrets emit 401/500 from dependency injection; ``init_db`` propagates SQLite
    errors at startup helpers; platform routes may return HTTP 403 when RBAC denies previews.

Audit Notes:
    Correlate SQLite rows (`backend/toolkit.db`) with ``platform_data/*.jsonl`` only when reviewers
    explicitly enable both stacks—each store represents a different persistence contract.

Engineering Notes:
    ``CORSMiddleware`` permissive defaults target local demos; tighten origins before exposing beyond
    loopback interfaces.
"""

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from platform_core.metrics import compute_platform_metrics
from platform_core.settings import get_settings
from platform_core.startup_checks import run_startup_checks, startup_state

try:
    from .billing import create_checkout_session, verify_webhook

    _BILLING_AVAILABLE = True
except ImportError:  # pragma: no cover - optional Stripe SDK for SaaS demo routes
    _BILLING_AVAILABLE = False

    def create_checkout_session(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("stripe package not installed")

    def verify_webhook(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("stripe package not installed")


from .engine import DiagnoseInput, classify_root_cause, detect_anomaly
from .jwt_auth import AuthUser, get_current_user
from .legacy_sqlite import (
    ensure_user_org_project,
    get_history,
    get_project_for_user,
    get_recent_metrics,
    get_subscription,
    get_usage,
    init_db,
    insert_diagnosis,
    insert_metric,
    month_key,
    try_increment_usage_with_limit,
    update_subscription,
)
from .live_observability import router as toolkit_obs_router
from .observability_metrics import bootstrap_labeled_metrics_from_storage
from .platform_fleet_routes import router as platform_fleet_router
from .platform_mdp_routes import router as platform_mdp_router
from .platform_routes import router as platform_router
from .platform_sre_routes import router as platform_sre_router
from .platform_v2_routes import router as platform_v2_router
from .prometheus_exporter import gauges_from_platform_metrics, render_prometheus_text
from .prometheus_exporter import inc as prom_inc
from .tracing import init_tracing

try:
    from .decision_intelligence import router as decision_intelligence_router
    from .decision_intelligence.logging_utils import configure_structured_logging
    from .decision_intelligence.store import init_schema_if_postgres
except ImportError:  # pragma: no cover
    decision_intelligence_router = None  # type: ignore[assignment]
    configure_structured_logging = None  # type: ignore[assignment]
    init_schema_if_postgres = None  # type: ignore[assignment]

_SUBSCRIPTION_EVENT_TYPES = frozenset(
    {
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "subscription_created",
        "subscription_updated",
        "subscription_canceled",
    }
)


def process_stripe_subscription_event(
    event_type: str, data_object: dict[str, Any]
) -> dict[str, Any] | None:
    """Apply subscription sync for recognized Stripe billing events.

    Returns:
        Summary dict when the event was handled; ``None`` when the event type is ignored.

    Raises:
        ValueError: When a subscription event arrives without ``metadata.org_id``.
    """
    if event_type not in _SUBSCRIPTION_EVENT_TYPES:
        return None

    metadata = data_object.get("metadata") or {}
    org_id = metadata.get("org_id")
    if not org_id:
        raise ValueError(
            f"Stripe subscription event {event_type!r} missing metadata.org_id; "
            "cannot sync subscription state."
        )

    status = data_object.get("status", "active")
    stripe_customer_id = data_object.get("customer")
    stripe_subscription_id = data_object.get("id")
    price_info = ((data_object.get("items") or {}).get("data") or [{}])[0]
    price_id = ((price_info.get("price") or {}).get("id")) or ""
    if "team" in price_id:
        plan = "team"
    elif "pro" in price_id:
        plan = "pro"
    else:
        plan = "free"
    if event_type in {"customer.subscription.deleted", "subscription_canceled"}:
        status = "canceled"
        plan = "free"
    update_subscription(
        org_id=str(org_id),
        plan=plan,
        status=status,
        stripe_customer_id=stripe_customer_id,
        stripe_subscription_id=stripe_subscription_id,
    )
    return {
        "processed": True,
        "org_id": str(org_id),
        "plan": plan,
        "status": status,
    }


_REPO_ROOT_MAIN = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT_MAIN) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT_MAIN))


class DiagnoseRequest(BaseModel):
    """Input payload for rule-based diagnosis endpoint."""

    ping: bool
    dns: bool
    https: bool
    proxy: bool
    time_wait: int = Field(ge=0)
    established: int = Field(ge=0)
    project_id: str | None = None


class DiagnoseResponse(BaseModel):
    """Output payload for diagnosis classification endpoint."""

    root_cause: str
    confidence: str
    recommendation: str
    risk: str
    anomaly: dict | None = None


class MonitorRequest(BaseModel):
    """Input payload for connection trend monitoring endpoint."""

    time_wait: int = Field(ge=0)
    established: int = Field(ge=0)
    project_id: str | None = None


class CheckoutRequest(BaseModel):
    """Input payload for creating Stripe checkout sessions."""

    org_id: str
    price_id: str
    success_url: str
    cancel_url: str


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Load typed config, run startup checks, initialize DB, manage outbox sweeper.

    Starts the optional classification-outbox sweeper (no-op when
    ``TRISK_OUTBOX_SWEEPER_ENABLED`` is off) and stops it on shutdown.
    """
    settings = get_settings()
    report = run_startup_checks(settings)
    startup_state.report = report
    if settings.fail_fast_on_startup and not report.ok:
        failed = [c.name for c in report.checks if c.status == "failed"]
        raise RuntimeError(f"startup checks failed: {', '.join(failed)}")
    bootstrap_labeled_metrics_from_storage()
    init_tracing("endpoint-reliability-platform")
    if configure_structured_logging is not None:
        configure_structured_logging()
    if init_schema_if_postgres is not None:
        init_schema_if_postgres()
    init_db()
    from backend.product_outbox_sweeper import start_outbox_sweeper, stop_outbox_sweeper

    start_outbox_sweeper()
    try:
        yield
    finally:
        stop_outbox_sweeper()


_settings = get_settings()
app = FastAPI(
    title="Endpoint Reliability Platform API",
    description=(
        "Local-first endpoint reliability platform with policy-gated remediation, "
        "event correlation, append-only audit, and dry-run defaults. "
        "No automatic repair — human approval required for destructive actions. "
        "Observation != proof · correlation != causation · policy ALLOW != safety guarantee."
    ),
    version=_settings.service_version,
    openapi_tags=[
        {
            "name": "platform",
            "description": "Fleet, incidents, correlation, policy-gated remediation",
        },
        {
            "name": "platform-v2",
            "description": "Versioned reliability pipeline (events, state, replay)",
        },
        {"name": "platform-sre", "description": "SRE incidents, RCA, MTTR, postmortems"},
        {"name": "platform-fleet", "description": "Fleet-scale ingest, dedup, partition replay"},
        {
            "name": "decision-intelligence",
            "description": "Events, evidence, decisions, outcomes, replay, and learning metrics",
        },
        {
            "name": "technology-risk-analytics",
            "description": "Read-only incidents, risk scores, control tests, executive reports",
        },
    ],
    lifespan=lifespan,
)

app.include_router(toolkit_obs_router)
app.include_router(platform_router)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Browser landing — OpenAPI Swagger UI."""
    return RedirectResponse(url="/docs")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    """Avoid noisy 404 when browsers request a favicon on the API host."""
    return Response(status_code=204)


@app.get("/health", tags=["health"])
def root_health() -> dict[str, str]:
    """Root liveness probe — ERP health fields plus demo vs standard mode."""
    try:
        from windows_network_toolkit import SERVICE_NAME, __version__
        from windows_network_toolkit.safety import is_demo_mode
    except ImportError:  # pragma: no cover
        demo = os.environ.get("DEMO_MODE", "").lower() in ("1", "true", "yes")
        service = "endpoint-reliability-decision-platform"
        version = "0.0.0"
    else:
        demo = is_demo_mode()
        service = SERVICE_NAME
        version = __version__
    return {
        "status": "ok",
        "service": service,
        "version": version,
        "mode": "demo" if demo else "standard",
    }


app.include_router(platform_mdp_router)
app.include_router(platform_v2_router, prefix="/platform")
app.include_router(platform_sre_router, prefix="/platform")
app.include_router(platform_fleet_router, prefix="/platform")
if decision_intelligence_router is not None:
    app.include_router(decision_intelligence_router)

try:
    from backend.canonical_routes import router as canonical_router

    app.include_router(canonical_router)
except ImportError as exc:  # pragma: no cover
    import logging

    logging.getLogger(__name__).warning("canonical_routes not mounted: %s", exc)

try:
    from windows_network_toolkit.platform.api import router as erp_platform_router

    app.include_router(erp_platform_router)
    _DASHBOARD_DIR = _REPO_ROOT_MAIN / "windows_network_toolkit" / "platform" / "dashboard"
    if _DASHBOARD_DIR.is_dir():
        app.mount(
            "/dashboard",
            StaticFiles(directory=str(_DASHBOARD_DIR), html=True),
            name="erp-dashboard",
        )
except ImportError:  # pragma: no cover
    pass

try:
    from src.api.routes_evidence_tree import router as proxy_evidence_router
    from src.api.routes_proxy_incidents import router as proxy_incidents_router

    app.include_router(proxy_incidents_router)
    app.include_router(proxy_evidence_router)
except ImportError:  # pragma: no cover
    pass

try:
    from backend.technology_risk_routes import router as technology_risk_router

    app.include_router(technology_risk_router)
except ImportError:  # pragma: no cover
    pass

try:
    from backend.v1_routes import router as trisk_v1_router

    app.include_router(trisk_v1_router)
except ImportError:  # pragma: no cover
    pass

try:
    from backend.decision_platform_routes import router as enterprise_router

    app.include_router(enterprise_router)
except ImportError as exc:  # pragma: no cover
    import logging

    logging.getLogger(__name__).warning("enterprise routes not mounted: %s", exc)

try:
    from backend.decision_context_routes import router as decision_context_router

    app.include_router(decision_context_router)
except ImportError as exc:  # pragma: no cover
    import logging

    logging.getLogger(__name__).warning("decision_context routes not mounted: %s", exc)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_origins_list(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def prometheus_request_counter(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Count HTTP requests for Prometheus scrape at ``GET /metrics``."""
    prom_inc("platform_http_requests_total")
    return await call_next(request)


@app.get("/metrics", include_in_schema=False)
def prometheus_metrics() -> Response:
    """Prometheus text exposition (counters + JSONL-derived gauges)."""
    metrics = compute_platform_metrics()
    gauges = gauges_from_platform_metrics(metrics)
    try:
        from platform_core.endpoint_observability import merge_endpoint_gauges

        gauges.update(merge_endpoint_gauges(metrics))
    except ImportError:  # pragma: no cover
        pass
    body = render_prometheus_text(gauges)
    try:
        from backend.decision_intelligence.metrics import render_prometheus_lines

        body = body.rstrip() + "\n" + render_prometheus_lines()
    except ImportError:  # pragma: no cover
        pass
    try:
        from backend.trisk_metrics import render_trisk_prometheus_lines

        extra = render_trisk_prometheus_lines()
        if extra:
            body = body.rstrip() + "\n" + "\n".join(extra) + "\n"
    except ImportError:  # pragma: no cover
        pass

    try:
        from src.platform_core.operability.metrics_registry import (
            render_prometheus_text as render_operability_metrics,
        )

        operability = render_operability_metrics()
        if operability:
            body = body.rstrip() + "\n" + operability
    except ImportError:  # pragma: no cover
        pass
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")


PLAN_LIMITS = {
    "free": 10,
    "pro": 500,
    "team": -1,  # unlimited
}


def _resolve_project(user: AuthUser, requested_project_id: str | None) -> dict:
    """Resolve an accessible project for the authenticated user.

    Args:
        user: Current authenticated user context.
        requested_project_id: Optional project override from request.

    Returns:
        dict: Project row containing `org_id` and `project_id`.

    Raises:
        HTTPException: 404 when project is not accessible by current user.
    """
    ensure_user_org_project(user.user_id, user.email)
    project = get_project_for_user(user.user_id, requested_project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found for current user.")
    return project


def _get_plan_limit(org_id: str) -> dict:
    """Resolve plan name and monthly diagnosis limit for an organization."""
    sub = get_subscription(org_id)
    plan = (sub.get("plan") or "free").lower()
    limit = PLAN_LIMITS.get(plan, 10)
    return {"plan": plan, "limit": limit}


@app.post("/diagnose", response_model=DiagnoseResponse)
def diagnose(req: DiagnoseRequest, user: AuthUser = Depends(get_current_user)) -> dict:
    """Run diagnosis workflow and persist resulting telemetry.

    Workflow:
        1) Resolve project scope and enforce plan usage limit.
        2) Detect anomaly from recent metric history.
        3) Classify root cause using deterministic rules.
        4) Persist diagnosis and metrics to SQLite.

    Side effects:
        - Increments usage counter for organization/month.
        - Writes diagnosis and metric rows to database.

    Idempotency:
        Not idempotent; each call increments usage and stores new records.

    Audit Notes:
        - What can go wrong: false positives from sparse history; over-limit
          rejection for heavy usage.
        - Detection: API 429 responses and stored diagnosis history.
        - Recovery: verify plan limits and rerun with updated telemetry.

    Args:
        req: Diagnosis signal payload.
        user: Authenticated user context (dependency-injected).

    Returns:
        dict: Classification result plus anomaly and usage metadata.

    Raises:
        HTTPException: 404 for missing project, 429 for plan limit exceeded.
    """
    project = _resolve_project(user, req.project_id)
    org_id = project["org_id"]
    project_id = project["project_id"]

    plan_info = _get_plan_limit(org_id)
    plan = plan_info["plan"]
    limit = plan_info["limit"]
    current_count = try_increment_usage_with_limit(org_id=org_id, limit=limit, month=month_key())
    if current_count is None:
        raise HTTPException(
            status_code=429,
            detail=f"Usage limit reached for plan '{plan}' ({limit}/month).",
        )

    recent_metrics = get_recent_metrics(project_id=project_id, limit=10)
    anomaly = detect_anomaly(req.time_wait, req.established, recent_metrics)
    result = classify_root_cause(
        DiagnoseInput(
            ping=req.ping,
            dns=req.dns,
            https=req.https,
            proxy=req.proxy,
            time_wait=req.time_wait,
            established=req.established,
        ),
        anomaly,
    )
    result["anomaly"] = anomaly
    insert_diagnosis(project_id=project_id, input_data=req.model_dump(), result=result)
    insert_metric(project_id=project_id, time_wait=req.time_wait, established=req.established)
    result["usage"] = {
        "org_id": org_id,
        "plan": plan,
        "month": month_key(),
        "diagnosis_count": current_count,
        "limit": limit if limit != -1 else "unlimited",
    }
    return result


@app.post("/monitor")
def monitor(req: MonitorRequest, user: AuthUser = Depends(get_current_user)) -> dict:
    """Persist connection counters and return anomaly assessment.

    Side effects:
        Writes one metric row to database.

    Idempotency:
        Not idempotent; repeated calls create additional metric rows.
    """
    project = _resolve_project(user, req.project_id)
    project_id = project["project_id"]
    recent_metrics = get_recent_metrics(project_id=project_id, limit=10)
    anomaly = detect_anomaly(req.time_wait, req.established, recent_metrics)
    metric_id, created_at = insert_metric(
        project_id=project_id,
        time_wait=req.time_wait,
        established=req.established,
    )
    return {
        "id": metric_id,
        "timestamp": created_at,
        "stored": True,
        "anomaly": anomaly,
    }


@app.get("/history")
def history(
    limit: int = 100,
    project_id: str | None = None,
    user: AuthUser = Depends(get_current_user),
) -> dict:
    """Return bounded diagnosis/metrics history for current project scope."""
    project = _resolve_project(user, project_id)
    safe_limit = max(1, min(limit, 500))
    return get_history(org_id=project["org_id"], project_id=project_id, limit=safe_limit)


@app.get("/usage")
def usage(user: AuthUser = Depends(get_current_user), project_id: str | None = None) -> dict:
    """Return current month usage and remaining diagnosis quota."""
    project = _resolve_project(user, project_id)
    org_id = project["org_id"]
    sub = get_subscription(org_id)
    u = get_usage(org_id, month=month_key())
    plan = (sub.get("plan") or "free").lower()
    limit = PLAN_LIMITS.get(plan, 10)
    remaining = "unlimited" if limit == -1 else max(0, limit - int(u["diagnosis_count"]))
    return {
        "org_id": org_id,
        "month": u["month"],
        "plan": plan,
        "status": sub.get("status", "active"),
        "diagnosis_count": int(u["diagnosis_count"]),
        "limit": limit if limit != -1 else "unlimited",
        "remaining": remaining,
    }


@app.post("/create-checkout-session")
def create_checkout(
    req: CheckoutRequest,
    user: AuthUser = Depends(get_current_user),
) -> dict:
    """Create Stripe checkout session for current user's organization.

    Side effects:
        Outbound API call to Stripe checkout endpoint.
    """
    if not _BILLING_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail=(
                "Billing unavailable: install project dependencies "
                "(pip install -e .) so the stripe package is present."
            ),
        )
    project = _resolve_project(user, None)
    if project["org_id"] != req.org_id:
        raise HTTPException(
            status_code=403, detail="Cannot create checkout for another organization."
        )

    session = create_checkout_session(
        customer_email=user.email,
        price_id=req.price_id,
        success_url=req.success_url,
        cancel_url=req.cancel_url,
        metadata={"org_id": req.org_id, "user_id": user.user_id},
    )
    return {"checkout_url": session.get("url"), "session_id": session.get("id")}


@app.post("/webhook")
async def webhook(request: Request) -> dict:
    """Validate Stripe webhook and synchronize subscription state.

    Side effects:
        - Verifies Stripe webhook signature.
        - Updates local subscription row when recognized billing events arrive.

    Idempotency:
        Best-effort idempotent for repeated webhook deliveries because updates
        overwrite current org subscription state.

    Audit Notes:
        - What can go wrong: invalid signature, missing org metadata, unknown
          event shape.
        - Detection: 400 invalid webhook responses and subscription mismatch.
        - Recovery: replay webhook after correcting secret/config metadata.
    """
    if not _BILLING_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail=(
                "Billing unavailable: install project dependencies "
                "(pip install -e .) so the stripe package is present."
            ),
        )
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = verify_webhook(payload, sig)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Invalid webhook: {exc}") from exc

    event_type = event.get("type", "")
    data_object = (event.get("data") or {}).get("object") or {}

    try:
        sync_result = process_stripe_subscription_event(event_type, data_object)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    response: dict[str, Any] = {"received": True, "type": event_type}
    if sync_result is not None:
        response.update(sync_result)
    else:
        response["processed"] = False
    return response

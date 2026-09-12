"""Technology Risk & Control Analytics API — read-only governance endpoints.

Module responsibility:
    Expose incidents, risk scores, control tests, and executive reports over HTTP without
    duplicating pipeline logic. All routes delegate to ``analytics_pipeline`` and ``reporting``.

System placement:
    Mounted from ``backend/main.py`` alongside legacy ``/platform/*`` and ``/v1/*`` routers.
    Root ``GET /health`` remains the ERP platform route; use ``GET /trisk/health`` here.

Key invariants:
    * Read-only — no registry mutation, remediation, or audit append.
    * Fixture paths restricted to ``tests/fixtures``, ``examples``, and toolkit examples.
    * Default data source: ``tests/fixtures/analytics_pipeline_fixture.json``.

Side effects:
    None on host state; reads fixture/audit files from disk per request.

Failure modes:
    HTTP 404 when fixture path not found; HTTP 403 when path outside allowlist.
    HTTP 400 on path resolution errors.

Audit Notes:
    * Responses include ``limitations[]`` — do not strip for UI summaries.
    * ``fixture`` query param is for demo/portfolio only; production should use audited ingest.
    * Recovery: point ``fixture`` at a known-good JSON under ``tests/fixtures``.

Engineering Notes:
    Separate from ``/platform/incidents`` (fleet JSONL) and ``/api/proxy/incidents`` (proxy store)
    to avoid breaking existing API consumers while providing governance-focused shapes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from windows_network_toolkit import SERVICE_NAME, __version__
from windows_network_toolkit.analytics_pipeline import run_endpoint_analytics_pipeline
from windows_network_toolkit.control_tests import INCIDENT_CONTROL_MAP, controls_for_incident_class
from windows_network_toolkit.reporting import build_executive_report

router = APIRouter(tags=["technology-risk-analytics"])

_REPO = Path(__file__).resolve().parent.parent
_DEFAULT_FIXTURE = _REPO / "tests" / "fixtures" / "analytics_pipeline_fixture.json"
_ALLOWED_FIXTURE_ROOTS = (
    _REPO / "tests" / "fixtures",
    _REPO / "examples",
    _REPO / "windows_network_toolkit" / "examples",
)


class HealthResponse(BaseModel):
    """Technology risk API health payload."""

    status: str = "ok"
    service: str = SERVICE_NAME
    version: str = __version__
    api: str = "technology-risk-analytics"
    positioning: str = (
        "Technology Risk & Control Analytics — not antivirus, EDR, or autonomous remediation."
    )


class IncidentSummary(BaseModel):
    """Subset of incident fields for OpenAPI documentation."""

    incident_id: str
    incident_class: str
    risk_level: str
    confidence: float
    human_interpretation: str = ""
    limitations: list[str] = Field(default_factory=list)


class RiskScoreOut(BaseModel):
    """Typed risk score entry for OpenAPI documentation."""

    incident_id: str | None = None
    incident_class: str = ""
    likelihood: str
    impact: str
    risk_score: float
    risk_level: str
    explanation: str
    human_review_recommended: bool = False
    limitations: list[str] = Field(default_factory=list)


class ControlTestOut(BaseModel):
    """Control test result shape for OpenAPI documentation."""

    control_id: str
    control_objective: str
    test_result: str
    risk: str
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommendation: str = ""


class ControlCatalogEntry(BaseModel):
    """Incident class to control ID mapping entry."""

    incident_class: str
    control_ids: list[str]


def _resolve_fixture_path(fixture: str | None) -> Path | None:
    """Resolve and validate a fixture path under allowed repository roots.

    Returns:
        Resolved path, or None when ``fixture`` is omitted (caller uses default).

    Raises:
        HTTPException: 404 not found, 403 outside allowlist, 400 on resolve failure.
    """
    if not fixture:
        return None
    path = Path(fixture)
    if not path.is_file():
        path = _REPO / fixture
    if not path.is_file():
        path = _DEFAULT_FIXTURE
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"fixture not found: {fixture}")
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not any(resolved.is_relative_to(root.resolve()) for root in _ALLOWED_FIXTURE_ROOTS if root.exists()):
        raise HTTPException(status_code=403, detail="fixture path outside allowed directories")
    return resolved


def _load_pipeline_payload(*, fixture: str | None = None) -> dict[str, Any]:
    """Run endpoint analytics pipeline from fixture file or default portfolio fixture."""
    fixture_path = _resolve_fixture_path(fixture)
    if fixture_path:
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        return run_endpoint_analytics_pipeline(fixture=data)
    return run_endpoint_analytics_pipeline(
        fixture=json.loads(_DEFAULT_FIXTURE.read_text(encoding="utf-8"))
    )


@router.get("/trisk/health", response_model=HealthResponse)
def trisk_health() -> HealthResponse:
    """Return technology risk analytics API health.

    Note:
        Root ``GET /health`` is served by ``windows_network_toolkit.platform.api`` (ERP).
    """
    return HealthResponse()


@router.get("/incidents", response_model=dict[str, Any])
def list_incidents(
    fixture: str | None = Query(default=None, description="Fixture path under tests/fixtures or examples"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List classified incidents from the evidence pipeline (read-only).

    Args:
        fixture: Optional JSON fixture path; defaults to portfolio fixture.
        limit: Page size (1–200).
        offset: Pagination offset.

    Returns:
        Paginated ``items``, ``total``, ``schema_version``, and ``limitations``.
    """
    payload = _load_pipeline_payload(fixture=fixture)
    items = payload.get("incidents") or []
    page = items[offset : offset + limit]
    return {
        "schema_version": payload.get("schema_version"),
        "total": len(items),
        "limit": limit,
        "offset": offset,
        "items": page,
        "limitations": payload.get("limitations") or [],
    }


@router.get("/risks", response_model=dict[str, Any])
def list_risks(
    fixture: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    """List typed risk scores derived from incidents and control tests.

    Returns:
        Paginated risk score items with schema_version ``technology_risk_scoring.v1``.
    """
    payload = _load_pipeline_payload(fixture=fixture)
    scores = payload.get("risk_scores") or []
    page = scores[offset : offset + limit]
    return {
        "schema_version": "technology_risk_scoring.v1",
        "total": len(scores),
        "limit": limit,
        "offset": offset,
        "items": page,
        "limitations": [
            "Risk scores are ordinal governance input, not malware verdicts.",
            *(payload.get("limitations") or []),
        ],
    }


@router.get("/controls", response_model=dict[str, Any])
def list_controls(
    fixture: str | None = Query(default=None),
    incident_class: str | None = Query(default=None),
) -> dict[str, Any]:
    """List control test results and the incident→control mapping catalog.

    Args:
        incident_class: When set, filter tests to controls mapped for that class.
    """
    payload = _load_pipeline_payload(fixture=fixture)
    tests = payload.get("control_tests") or []
    if incident_class:
        allowed = set(controls_for_incident_class(incident_class))
        tests = [t for t in tests if t.get("control_id") in allowed]
    catalog = [
        ControlCatalogEntry(incident_class=cls, control_ids=ids).model_dump()
        for cls, ids in sorted(INCIDENT_CONTROL_MAP.items())
    ]
    return {
        "schema_version": payload.get("schema_version"),
        "control_tests": tests,
        "incident_control_map": catalog,
        "limitations": payload.get("limitations") or [],
    }


@router.get("/reports/executive", response_model=dict[str, Any])
def executive_report(
    fixture: str | None = Query(default=None),
) -> dict[str, Any]:
    """Return executive governance report — KPIs, risk scores, control summary (read-only)."""
    payload = _load_pipeline_payload(fixture=fixture)
    return build_executive_report(payload)


# --- Browser-profile differential (read-only / preview) ---


def _resolve_browser_fixture(path: str | None) -> Path | None:
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        p = _REPO / path
    if not p.is_file():
        raise HTTPException(status_code=404, detail="fixture not found")
    resolved = p.resolve()
    if not any(str(resolved).startswith(str(root.resolve())) for root in _ALLOWED_FIXTURE_ROOTS):
        raise HTTPException(status_code=403, detail="fixture path outside allowlist")
    return resolved


@router.get("/trisk/browser/diff", response_model=dict[str, Any])
def browser_diff(
    url: str = Query(..., description="Target URL"),
    browser: str = Query(default="auto"),
    fixture: str | None = Query(default=None),
) -> dict[str, Any]:
    """Read-only browser differential result (prefer fixture for demos)."""
    from windows_network_toolkit.diagnostics.browser_profile import run_browser_diff

    fix = _resolve_browser_fixture(fixture)
    if fix is not None:
        return run_browser_diff(url, browser=browser, fixture=fix).to_dict()
    # Live path is still read-only but may touch OS network + profile metadata
    return run_browser_diff(url, browser=browser, proof=False).to_dict()


@router.get("/trisk/browser/profiles", response_model=dict[str, Any])
def browser_profiles(browser: str = Query(default="auto")) -> dict[str, Any]:
    """Handle the GET request for browser profiles.
    
    Args:
        browser: The browser value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    from windows_network_toolkit.diagnostics.browser_profile import run_browser_profile_inspect

    return run_browser_profile_inspect(browser=browser)


@router.get("/trisk/browser/site-state", response_model=dict[str, Any])
def browser_site_state(
    domain: str = Query(...),
    browser: str = Query(default="auto"),
) -> dict[str, Any]:
    """Handle the GET request for browser site state.
    
    Args:
        domain: The domain value supplied by the caller.
        browser: The browser value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    from windows_network_toolkit.diagnostics.browser_profile import run_browser_site_state

    return run_browser_site_state(domain, browser=browser)


@router.get("/trisk/browser/extensions", response_model=dict[str, Any])
def browser_extensions(browser: str = Query(default="auto")) -> dict[str, Any]:
    """Handle the GET request for browser extensions.
    
    Args:
        browser: The browser value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    from windows_network_toolkit.diagnostics.browser_profile.adapters import get_adapter

    adapter = get_adapter(browser)
    profiles = adapter.discover_profiles()
    default = next((p for p in profiles if p.is_default), profiles[0] if profiles else None)
    if default is None:
        return {"extensions": [], "limitations": ["No profile found."]}
    exts = adapter.collect_extension_metadata(default)
    return {
        "browser": adapter.name,
        "profile_id": default.profile_id,
        "extensions": [e.model_dump(mode="json") for e in exts],
        "limitations": ["Extension metadata only — not malware attribution."],
    }


@router.get("/trisk/browser/policies", response_model=dict[str, Any])
def browser_policies(browser: str = Query(default="auto")) -> dict[str, Any]:
    """Handle the GET request for browser policies.
    
    Args:
        browser: The browser value supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    from windows_network_toolkit.diagnostics.browser_profile.adapters import get_adapter

    adapter = get_adapter(browser)
    policies = adapter.collect_policy_metadata()
    return {
        "browser": adapter.name,
        "policies": [p.model_dump(mode="json") for p in policies],
        "limitations": ["Policy discovery is best-effort metadata."],
    }


class HarCompareBody(BaseModel):
    """Represent har compare body data used by the toolkit.
    
    Attributes:
        normal_har: Field or variant describing normal har evidence or state.
        private_har: Field or variant describing private har evidence or state.
        target_url: Field or variant describing target url evidence or state.
        browser: Field or variant describing browser evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    normal_har: dict[str, Any]
    private_har: dict[str, Any]
    target_url: str = "https://example.invalid/"
    browser: str = "auto"


@router.post("/trisk/browser/har/compare", response_model=dict[str, Any])
def browser_har_compare(body: HarCompareBody) -> dict[str, Any]:
    """Compare two HAR payloads (already client-side; server redacts again)."""
    import tempfile
    from pathlib import Path

    from windows_network_toolkit.diagnostics.browser_profile import run_browser_diff

    with tempfile.TemporaryDirectory() as td:
        n = Path(td) / "normal.har"
        p = Path(td) / "private.har"
        n.write_text(json.dumps(body.normal_har), encoding="utf-8")
        p.write_text(json.dumps(body.private_har), encoding="utf-8")
        return run_browser_diff(
            body.target_url,
            browser=body.browser,
            proof=True,
            normal_har=n,
            private_har=p,
            inspect_profile=False,
        ).to_dict()


class RepairPreviewBody(BaseModel):
    """Represent repair preview body data used by the toolkit.
    
    Attributes:
        domain: Field or variant describing domain evidence or state.
        browser: Field or variant describing browser evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    domain: str
    browser: str = "auto"


@router.post("/trisk/browser/repair/preview", response_model=dict[str, Any])
def browser_repair_preview(body: RepairPreviewBody) -> dict[str, Any]:
    """Handle the POST request for browser repair preview.
    
    Args:
        body: Request or domain payload supplied by the caller.
    
    Returns:
        Response payload serialized by FastAPI for the caller.
    
    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    from windows_network_toolkit.diagnostics.browser_profile import run_repair_preview

    return run_repair_preview(body.domain, browser=body.browser)

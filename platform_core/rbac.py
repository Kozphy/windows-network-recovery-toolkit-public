"""Header-derived authorization helpers for localhost FastAPI ``/platform/*`` demos.

Module responsibility:
    Translate ``X-Operator-*`` HTTP headers into :class:`DemoPrincipal` records and expose explicit
    ``assert_can_*`` guardrails aligning with remediation, ingestion, and read surfaces.

System placement:
    Imported by dependencies inside :mod:`backend.platform_routes` and exercised via pytest RBAC matrices.

Key invariants:
    * Roles are **portfolio simulations** — not substitutes for SSO/IdP-backed authorization.
    * Default missing headers resolve to ``operator`` / ``anonymous`` per :func:`parse_demo_principal`.
    * ``security`` string header aliases to ``security_auditor`` for ergonomic curl demos only.

Decision intent:
    * ``viewer`` never mutates ingestion or remediation preview paths—read-only KPI consumption.
    * ``operator`` may stage remediation previews plus **dry-run** executions exclusively.
    * ``admin`` may drive live executions still bounded by remediation registry + policy duplicates downstream.
    * ``security_auditor`` focuses on attribution/audit readability without widening write attack surface.

Raises:
    Every ``assert_can_*`` helper raises ``fastapi.HTTPException`` status ``403`` on denial—consistent with synchronous FastAPI error surface.

Recovery guidance:
    When operators receive unexpected ``403``, re-check header casing (``X-Operator-Role``) and upgraded RBAC matrices documented in ``docs/rbac_and_remediation.md``.

Audit Notes:
    Denied attempts should still yield client-visible ``403`` without server-side mutations—grep FastAPI logs for repeated failures indicating automation using stale roles post policy change.

Engineering Notes:
    Guards remain intentionally synchronous and side-effect-free (besides exceptions) making them trivially unit-testable without DB fixtures.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

from fastapi import HTTPException

Role = Literal["viewer", "operator", "admin", "security", "security_auditor"]


@dataclass(frozen=True)
class DemoPrincipal:
    """Lightweight RBAC projection parsed from inbound headers."""

    operator_id: str
    role: Role


def _normalize_role(raw: str | None) -> Role:
    """Map raw header/environment strings onto supported :class:`Role` literals."""

    r = (raw or os.getenv("PLATFORM_DEFAULT_ROLE") or "operator").strip().lower()
    if r == "security":
        return "security_auditor"
    if r in ("viewer", "operator", "admin", "security_auditor"):
        return r  # type: ignore[return-value]
    return "operator"


def parse_demo_principal(
    x_operator_id: str | None,
    x_operator_role: str | None,
) -> DemoPrincipal:
    """Hydrate immutable principal honoring environment fallbacks.

    Args:
        x_operator_id: ``X-Operator-Id`` header or ``PLATFORM_DEFAULT_OPERATOR_ID``.
        x_operator_role: ``X-Operator-Role`` header (``security`` normalizes internally).

    Returns:
        Frozen :class:`DemoPrincipal` suitable for Dependency injection caches.

    Side effects:
        Reads environment lazily — safe for multiprocess demos.

    Examples:
        ``parse_demo_principal(None, "security")`` resolves ``role='security_auditor'``.
    """

    oid = (x_operator_id or os.getenv("PLATFORM_DEFAULT_OPERATOR_ID") or "anonymous").strip()
    role = _normalize_role(x_operator_role)
    return DemoPrincipal(operator_id=oid, role=role)


def assert_can_preview(principal: DemoPrincipal) -> None:
    """Ensure caller may instantiate remediation previews."""

    if principal.role == "viewer":
        raise HTTPException(status_code=403, detail="viewer is read-only")
    if principal.role == "security_auditor":
        raise HTTPException(status_code=403, detail="security role may view audit/attribution only")
    if principal.role not in ("operator", "admin"):
        raise HTTPException(
            status_code=403, detail="remediation preview requires operator or admin"
        )


def assert_can_execute(principal: DemoPrincipal, *, dry_run: bool) -> None:
    """Authorize remediation execution paths discriminating ``dry_run`` vs live."""

    if principal.role not in ("operator", "admin"):
        raise HTTPException(
            status_code=403, detail="remediation execute requires operator or admin"
        )
    if principal.role == "operator" and not dry_run:
        raise HTTPException(
            status_code=403,
            detail="operator role may only run dry_run executions; admin executes allowlisted repair",
        )


def assert_can_read_audit(principal: DemoPrincipal) -> None:
    """Restrict audit JSONL tails to privileged reader roles."""

    if principal.role not in ("admin", "security_auditor"):
        raise HTTPException(status_code=403, detail="audit log restricted to admin or security")


def assert_can_read_attribution(principal: DemoPrincipal) -> None:
    """Allow remediation triage + security insight without granting ingestion rights."""

    if principal.role not in ("operator", "admin", "security_auditor"):
        raise HTTPException(
            status_code=403,
            detail="attribution detail requires operator, admin, or security",
        )


def assert_can_read_normalized_events(principal: DemoPrincipal) -> None:
    """Gate normalized telemetry stream readability."""

    if principal.role not in ("viewer", "operator", "admin", "security_auditor"):
        raise HTTPException(status_code=403, detail="events list requires viewer or higher")


def assert_can_read_incidents(principal: DemoPrincipal) -> None:
    """Gate incident clustering API output."""

    if principal.role not in ("viewer", "operator", "admin", "security_auditor"):
        raise HTTPException(status_code=403, detail="incidents requires viewer or higher")


def assert_viewer_or_above(principal: DemoPrincipal) -> None:
    """Reserved hook for tightening future enumerated roles."""

    _ = principal


def assert_can_read_metrics(principal: DemoPrincipal) -> None:
    """Validate metrics endpoint consumers (portfolio-safe KPI reads)."""

    if principal.role not in ("viewer", "operator", "admin", "security_auditor"):
        raise HTTPException(status_code=403, detail="invalid role for metrics")


def assert_can_write_platform_payload(principal: DemoPrincipal) -> None:
    """Deny ingestion for read-oriented personas (heartbeat/snapshots/events)."""

    if principal.role == "viewer":
        raise HTTPException(status_code=403, detail="viewer is read-only")
    if principal.role == "security_auditor":
        raise HTTPException(
            status_code=403, detail="security role is read-only except audit/attribution views"
        )
    if principal.role not in ("operator", "admin"):
        raise HTTPException(status_code=403, detail="ingestion requires operator or admin")

"""RBAC roles for /v1 technology-risk API (demo token auth)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from fastapi import HTTPException


class V1Role(StrEnum):
    """Represent v1 role data used by the toolkit.

    Attributes:
        ADMIN: Field or variant describing a d m i n evidence or state.
        OPERATOR: Field or variant describing o p e r a t o r evidence or state.
        RISK_REVIEWER: Field or variant describing r i s k r e v i e w e r evidence or state.
        AUDITOR_READONLY: Field or variant describing a u d i t o r r e a d o n l y evidence or state.
        DEMO_VIEWER: Field or variant describing d e m o v i e w e r evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    ADMIN = "admin"
    OPERATOR = "operator"
    RISK_REVIEWER = "risk_reviewer"
    AUDITOR_READONLY = "auditor_readonly"
    DEMO_VIEWER = "demo_viewer"


@dataclass(frozen=True)
class V1Principal:
    """Represent v1 principal data used by the toolkit.

    Attributes:
        actor_id: Field or variant describing actor id evidence or state.
        role: Field or variant describing role evidence or state.
        tenant_id: Field or variant describing tenant id evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    actor_id: str
    role: V1Role
    tenant_id: str = "default"


def assert_can_manage_policy(principal: V1Principal) -> None:
    """Assert can manage policy.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    if principal.role not in (V1Role.ADMIN,):
        raise HTTPException(status_code=403, detail="policy management requires admin")


def assert_can_run_pipeline(principal: V1Principal) -> None:
    """Assert can run pipeline.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if principal.role not in (V1Role.ADMIN, V1Role.OPERATOR, V1Role.RISK_REVIEWER):
        raise HTTPException(
            status_code=403, detail="pipeline requires operator, reviewer, or admin"
        )


def parse_role(raw: str | None) -> V1Role:
    """Parse role.

    Args:
        raw: The raw value supplied by the caller.

    Returns:
        The V1Role result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if not raw:
        return V1Role.DEMO_VIEWER
    key = raw.strip().lower()
    for role in V1Role:
        if role.value == key:
            return role
    return V1Role.DEMO_VIEWER


def assert_can_ingest(principal: V1Principal) -> None:
    """Assert can ingest.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if principal.role not in (V1Role.ADMIN, V1Role.OPERATOR):
        raise HTTPException(status_code=403, detail="ingest requires operator or admin")


def assert_can_review(principal: V1Principal) -> None:
    """Assert can review.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if principal.role not in (V1Role.ADMIN, V1Role.RISK_REVIEWER):
        raise HTTPException(status_code=403, detail="review requires risk_reviewer or admin")


def assert_can_read_incidents(principal: V1Principal) -> None:
    """Assert can read incidents.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if principal.role == V1Role.DEMO_VIEWER:
        return
    if principal.role in (
        V1Role.ADMIN,
        V1Role.OPERATOR,
        V1Role.RISK_REVIEWER,
        V1Role.AUDITOR_READONLY,
    ):
        return
    raise HTTPException(status_code=403, detail="read incidents denied")


def assert_can_read_audit_reports(principal: V1Principal) -> None:
    """Assert can read audit reports.

    Args:
        principal: The principal value supplied by the caller.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    if principal.role in (
        V1Role.ADMIN,
        V1Role.RISK_REVIEWER,
        V1Role.AUDITOR_READONLY,
        V1Role.DEMO_VIEWER,
    ):
        return
    raise HTTPException(status_code=403, detail="audit/report read denied")

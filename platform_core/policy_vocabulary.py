"""Canonical tri-state vocabulary for remediation policy surfaces.

Maps the structured gate :class:`~platform_core.policy.engine.StructuredPolicyDecision`
(``execute_allowed`` / ``preview_allowed`` / ``reason_codes``) to stable **ALLOW** /
**PREVIEW** / **BLOCK** labels used in reasoning outputs and dashboards, and bridges
historical ``product_contract`` string values (``allow`` / ``preview_only`` / ``blocked``).

Phase 1 scope: additive helpers only — no behavioral change to :func:`~platform_core.policy.engine.evaluate`.
"""

from __future__ import annotations

from typing import Literal

from platform_core.policy.engine import StructuredPolicyDecision

PolicyTriState = Literal["ALLOW", "PREVIEW", "BLOCK"]

# Historical / HTTP-facing decision strings on :class:`~platform_core.product_contract.PolicyResult`.
ProductContractDecision = Literal["allow", "preview_only", "blocked"]


def structured_decision_to_tri_state(decision: StructuredPolicyDecision) -> PolicyTriState:
    """Derive tri-state label from structured preview/execute flags.

    Precedence:
        1. ``execute_allowed`` → **ALLOW** (routes may still require typed confirmation).
        2. ``preview_allowed`` → **PREVIEW**
        3. otherwise → **BLOCK**
    """
    if decision.execute_allowed:
        return "ALLOW"
    if decision.preview_allowed:
        return "PREVIEW"
    return "BLOCK"


def tri_state_to_product_contract_decision(tri: PolicyTriState) -> ProductContractDecision:
    """Map tri-state vocabulary to :mod:`platform_core.product_contract` decision strings."""
    if tri == "ALLOW":
        return "allow"
    if tri == "PREVIEW":
        return "preview_only"
    return "blocked"


def product_contract_decision_to_tri_state(decision: str) -> PolicyTriState | None:
    """Best-effort parse of legacy decision strings; unknown values return ``None``."""
    normalized = (decision or "").strip().lower()
    if normalized == "allow":
        return "ALLOW"
    if normalized in {"preview_only", "preview"}:
        return "PREVIEW"
    if normalized in {"blocked", "block"}:
        return "BLOCK"
    return None


def explain_tri_state(tri: PolicyTriState) -> str:
    """Short operator-facing gloss (not a legal or forensic claim)."""
    return {
        "ALLOW": "Structured policy permits live execution subject to route confirmation and registry gates.",
        "PREVIEW": "Preview or dry-run only; live execution is not authorized by structured policy alone.",
        "BLOCK": "Neither preview nor live execution is permitted under current policy signals.",
    }[tri]

"""Policy engine — vocabulary adapter over existing guardrails.

Module responsibility:
    Map ``DecisionResult`` incident types to allowed/blocked action lists for API and
    analytics layers — preview-first, confirmation for destructive paths.

System placement:
    Used by decision platform adapters; complements ``run_proxy_disable`` policy in
    ``platform.decision_engine``.

Key invariants:
    * ``dry_run=True`` keeps disable actions blocked even when incident allows preview.
    * ``HUMAN_REVIEW_REQUIRED`` blocks disable/stop for suspicious/MITM triage labels.

Side effects:
    None — pure policy evaluation.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from .decision_model import DecisionResult, IncidentType

CONFIRMATION_REQUIRED_ACTIONS = frozenset(
    {
        "DISABLE_WININET_PROXY_WITH_CONFIRMATION",
        "STOP_LISTENER_WITH_CONFIRMATION",
        "STOP_REVERTER_WITH_CONFIRMATION",
        "REGISTRY_MODIFICATION",
        "DNS_FLUSH",
        "FIREWALL_RESET",
        "ADAPTER_RESET",
    }
)


class PolicyOutcome(StrEnum):
    """High-level policy gate outcome for decision platform consumers."""

    ALLOW_PREVIEW = "ALLOW_PREVIEW"
    ALLOW_WITH_CONFIRMATION = "ALLOW_WITH_CONFIRMATION"
    BLOCK_UNSAFE_ACTION = "BLOCK_UNSAFE_ACTION"
    REQUIRE_ADMIN = "REQUIRE_ADMIN"
    REQUIRE_ROLLBACK_PLAN = "REQUIRE_ROLLBACK_PLAN"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


def evaluate_policy(
    decision: DecisionResult,
    *,
    dry_run: bool = True,
    has_admin: bool = False,
    evidence_level: str | None = None,
) -> dict[str, Any]:
    """Evaluate allowed and blocked actions for a decision under dry-run posture.

    Args:
        decision: Structured decision with incident type and recommended action.
        dry_run: When True, destructive apply paths remain blocked/preview-only.
        has_admin: Whether operator has admin elevation for listener stop actions.
        evidence_level: Optional evidence tier hint (e.g. ``OBSERVED_ONLY``).

    Returns:
        Dict with ``outcome``, ``allowed_actions``, ``blocked_actions``, and ``rationale``.

    Side effects:
        None.

    Audit Notes:
        ``ALLOW_PREVIEW`` does not authorize live registry mutation — typed confirmation
        still required in ``proxy_remediation``.
    """
    outcome = PolicyOutcome.ALLOW_PREVIEW
    blocked: list[str] = []
    allowed: list[str] = ["observe", "export_report", "replay"]

    if decision.human_review_required or decision.incident_type in {
        IncidentType.SUSPICIOUS_PROXY,
        IncidentType.POSSIBLE_MITM_RISK,
    }:
        outcome = PolicyOutcome.HUMAN_REVIEW_REQUIRED
        blocked.extend(["disable_wininet_proxy", "stop_proxy_listener", "stop_proxy_reverter"])

    elif decision.requires_confirmation:
        outcome = PolicyOutcome.ALLOW_WITH_CONFIRMATION
        if decision.recommended_action in CONFIRMATION_REQUIRED_ACTIONS or decision.requires_confirmation:
            allowed.append("remediation_preview")

    if decision.incident_type in {
        IncidentType.WININET_PROXY_DRIFT,
        IncidentType.PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS,
    }:
        allowed.append("disable_wininet_proxy")
        if not dry_run:
            blocked.append("disable_wininet_proxy")  # tests/API must stay preview-first

    if decision.incident_type == IncidentType.WRITER_AND_LISTENER_MATCH:
        allowed.append("stop_proxy_listener")
        if not has_admin:
            outcome = PolicyOutcome.REQUIRE_ADMIN

    if decision.recommended_action.startswith("DISABLE") or decision.recommended_action.startswith("STOP"):
        if outcome == PolicyOutcome.ALLOW_PREVIEW:
            outcome = PolicyOutcome.REQUIRE_ROLLBACK_PLAN

    if evidence_level == "OBSERVED_ONLY" and decision.confidence < 0.7:
        blocked.append("disable_wininet_proxy")
        outcome = PolicyOutcome.BLOCK_UNSAFE_ACTION if not dry_run else PolicyOutcome.ALLOW_PREVIEW

    return {
        "outcome": outcome.value,
        "dry_run": dry_run,
        "allowed_actions": sorted(set(allowed)),
        "blocked_actions": sorted(set(blocked)),
        "requires_confirmation": decision.requires_confirmation,
        "confirmation_actions": [
            a for a in CONFIRMATION_REQUIRED_ACTIONS if a in decision.recommended_action
        ],
        "rationale": (
            "Policy permission is not a safety guarantee. "
            "Destructive actions require preview, typed confirmation, rollback plan, and audit logging."
        ),
    }

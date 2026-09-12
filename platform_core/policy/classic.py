"""Classic policy predicates (risk tiers, remediation previews) — unchanged public surface."""

from __future__ import annotations

import re
import uuid
from typing import Any, Literal

from pydantic import BaseModel

from platform_core.models import (
    FailureEvent,
    RemediationPolicy,
    RemediationPreview,
    RequestSurface,
    RollbackPreviewFields,
    utc_now_iso,
)
from platform_core.remediation_registry import (
    build_action_registry_legacy_dict,
    get_remediation_action,
)
from src.platform_core.remediation.rollback import (
    build_proposed_mutation_preview,
    build_rollback_preview_package,
    capture_pre_change_snapshot,
)

RiskName = Literal["read_only", "low", "medium", "high", "forbidden"]

DEFAULT_POLICY = RemediationPolicy()

ACTION_REGISTRY: dict[str, dict[str, Any]] = build_action_registry_legacy_dict()


class PolicyDecision(BaseModel):
    """Serializable policy outcome (historic shape used by routers)."""

    allowed: bool
    reason: str
    effective_risk: RiskName = "read_only"


def require_typed_confirmation(action_name: str) -> str:
    """Evaluate the require typed confirmation condition.

    Args:
        action_name: Value supplied by the caller for action name.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    defn = get_remediation_action(action_name)
    if defn is None:
        return ""
    return defn.confirmation_phrase


def evaluate_action(
    action_name: str,
    requested_surface: RequestSurface,
    policy: RemediationPolicy | None = None,
) -> PolicyDecision:
    """Registry-first allow/deny (does not inspect operator RBAC roles)."""

    pol = policy or DEFAULT_POLICY
    defn = get_remediation_action(action_name)
    if defn is None:
        return PolicyDecision(allowed=False, reason="unknown_action", effective_risk="forbidden")

    risk_level = defn.risk_level
    if risk_level == "forbidden":
        return PolicyDecision(allowed=False, reason="forbidden_action", effective_risk="forbidden")
    if risk_level == "high":
        return PolicyDecision(
            allowed=False, reason="high_risk_blocked_from_platform", effective_risk="high"
        )

    if defn.allowed_surfaces and requested_surface not in defn.allowed_surfaces:
        return PolicyDecision(
            allowed=False, reason="surface_not_allowed", effective_risk=risk_level
        )
    if requested_surface == "api" and not pol.can_run_from_api:
        return PolicyDecision(
            allowed=False, reason="api_disabled_by_policy", effective_risk=risk_level
        )
    if requested_surface == "cli" and not pol.can_run_from_cli:
        return PolicyDecision(
            allowed=False, reason="cli_disabled_by_policy", effective_risk=risk_level
        )
    if risk_level not in pol.allowed_risk_levels:
        return PolicyDecision(
            allowed=False, reason="risk_level_not_allowed", effective_risk=risk_level
        )
    if action_name in pol.forbidden_actions:
        return PolicyDecision(
            allowed=False, reason="action_forbidden_by_policy", effective_risk=risk_level
        )
    return PolicyDecision(allowed=True, reason="ok", effective_risk=risk_level)


def build_preview(
    failure_event: FailureEvent,
    recommended_action: str,
    *,
    requested_surface: RequestSurface = "api",
    policy: RemediationPolicy | None = None,
) -> RemediationPreview:
    """Build a preview row layered on classic :func:`evaluate_action`."""

    pol = policy or DEFAULT_POLICY
    defn = get_remediation_action(recommended_action)
    if defn is None:
        return RemediationPreview(
            preview_id=str(uuid.uuid4()),
            endpoint_id=failure_event.endpoint_id,
            failure_event_id=failure_event.event_id,
            proposed_action=recommended_action,
            risk_level="high",
            rationale=failure_event.summary or "Unknown action key.",
            commands_preview=[],
            rollback_plan="",
            requires_typed_confirmation=True,
            confirmation_phrase="",
            allowed_by_policy=False,
            policy_reason="unknown_action",
            created_at=utc_now_iso(),
        )

    risk = defn.risk_level
    if risk not in ("read_only", "low", "medium", "high", "forbidden"):
        risk = "medium"
    commands: list[str] = []
    if defn.script_path:
        commands.append(f"scripts\\\\{defn.script_path}  (allowlisted)")
    if defn.manual_only and not defn.script_path:
        commands.append(
            "[manual] follow FailureBlock / operator runbook; no allowlisted .bat in prototype"
        )

    pd = evaluate_action(recommended_action, requested_surface, pol)
    needs_confirm = pol.requires_confirmation and risk in ("low", "medium")

    rollback_preview: RollbackPreviewFields | None = None
    if defn.rollback_plan:
        snapshot = capture_pre_change_snapshot(
            endpoint_id=failure_event.endpoint_id,
            incident_id=failure_event.event_id,
        )
        mutation = build_proposed_mutation_preview(
            action_id=recommended_action,
            endpoint_id=failure_event.endpoint_id,
        )
        pkg = build_rollback_preview_package(
            endpoint_id=failure_event.endpoint_id,
            incident_id=failure_event.event_id,
            action_id=recommended_action,
            pre_change_snapshot=snapshot,
            proposed_mutation=mutation,
            dry_run=True,
        )
        rb = pkg["rollback_preview"]
        rollback_preview = RollbackPreviewFields(
            rollback_preview_id=str(pkg["rollback_preview_id"]),
            pre_change_snapshot=pkg["pre_change_snapshot"],
            proposed_mutation_preview=pkg["proposed_mutation_preview"],
            human_approval_token_required=bool(pkg["human_approval_token"]["required"]),
            reversible_action_record=pkg["reversible_action_record"],
            rollback_steps=list(rb["steps"]),
            required_confirmation=str(rb["required_confirmation"]),
            dry_run=bool(rb["dry_run"]),
            limitations=list(rb["limitations"]),
        )

    return RemediationPreview(
        preview_id=str(uuid.uuid4()),
        endpoint_id=failure_event.endpoint_id,
        failure_event_id=failure_event.event_id,
        proposed_action=recommended_action,
        risk_level=risk,  # type: ignore[arg-type]
        rationale=failure_event.summary or "See FailureBlock / event linkage.",
        commands_preview=commands,
        rollback_plan=defn.rollback_plan,
        rollback_preview=rollback_preview,
        requires_typed_confirmation=needs_confirm and bool(defn.confirmation_phrase),
        confirmation_phrase=defn.confirmation_phrase,
        allowed_by_policy=pd.allowed,
        policy_reason=pd.reason,
        created_at=utc_now_iso(),
    )


def validate_confirmation_phrase(action_name: str, phrase: str) -> bool:
    """Evaluate the validate confirmation phrase condition.

    Args:
        action_name: Value supplied by the caller for action name.
        phrase: Value supplied by the caller for phrase.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    expected = require_typed_confirmation(action_name)
    if not expected:
        return True
    return phrase.strip() == expected


def is_shell_injection(text: str) -> bool:
    """Evaluate the is shell injection condition.

    Args:
        text: Value supplied by the caller for text.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    if re.search(r"[;&|`$]", text):
        return True
    if "\n" in text or "\r" in text:
        return True
    return False

"""Unified remediation gate combining registry risk, RBAC norms, and preview/execute split.

Live execution stays **deny-by-default**: only ``admin`` may receive ``execute_allowed=True`` for
eligible allowlisted registry actions pending typed confirmation enforced by callers.

Audit Notes:
    Misconfigured ``reason_codes`` hide operator/admin gaps—diff ``StructuredPolicyDecision`` responses against
    ``platform_data/audit.jsonl`` rows for the same correlation id. Recovery requires adjusting ``RemediationPolicy``
    fixtures or elevating role explicitly; never bypass ``allow_arbitrary_shell`` in production paths (tests only flag).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from platform_core.models import RemediationPolicy, RequestSurface, utc_now_iso
from platform_core.policy.classic import DEFAULT_POLICY, evaluate_action
from platform_core.remediation_registry import canonical_action_name, get_remediation_action

RiskName = Literal["read_only", "low", "medium", "high", "forbidden"]

OperatorRole = Literal["viewer", "operator", "admin", "security_auditor"]

# Alias "security" headers normalize to security_auditor in :mod:`platform_core.rbac`.


class SignalSnapshot(BaseModel):
    """Redacted telemetry slice — extra keys tolerated for deterministic fixtures/tests."""

    model_config = {"extra": "allow"}

    summary: str = ""
    dns_ok: bool | None = None
    winsock_hints: dict[str, Any] = Field(default_factory=dict)


class OperatorContext(BaseModel):
    """Who and where the remediation decision originates (portfolio demo semantics)."""

    role: OperatorRole = "operator"
    surface: RequestSurface = "api"


class StructuredPolicyDecision(BaseModel):
    """Machine-consumable policy gate (distinct from legacy :class:`PolicyDecision`)."""

    execute_allowed: bool = False
    preview_allowed: bool = False
    reason_codes: list[str] = Field(default_factory=list)
    required_role: str = "admin"
    required_confirmation: str | None = None
    risk_tier: RiskName = "read_only"
    timestamp: str = Field(default_factory=utc_now_iso)


def evaluate(
    signal_snapshot: SignalSnapshot | dict[str, Any] | None,
    remediation_action: str | None,
    operator_context: OperatorContext,
    policy: RemediationPolicy | None = None,
    *,
    allow_arbitrary_shell: bool = False,
) -> StructuredPolicyDecision:
    """Evaluate remediation gate for telemetry + suggested action key.

    Args:
        signal_snapshot: Optional telemetry (privacy-scrubbed by upstream collectors).
        remediation_action: Registry key such as ``reset_proxy`` before canonicalization.
        operator_context: Role + ingress surface demo headers map to here.
        policy: Optional org policy overriding defaults.
        allow_arbitrary_shell: Must remain ``False`` — present only so tests prove the flag is dead.

    Returns:
        Structured decision separating preview allowance from authenticated live execution.
    """

    reason_codes: list[str] = []
    pol = policy or DEFAULT_POLICY

    if allow_arbitrary_shell:
        reason_codes.append("arbitrary_shell_forbidden_even_if_requested")
        return StructuredPolicyDecision(
            execute_allowed=False,
            preview_allowed=False,
            reason_codes=reason_codes,
            required_role="admin",
            risk_tier="forbidden",
        )

    _ = (
        signal_snapshot
        if isinstance(signal_snapshot, SignalSnapshot)
        else SignalSnapshot(**(signal_snapshot or {}))
    )

    if operator_context.role == "viewer":
        reason_codes.append("viewer_preview_blocked")
        return StructuredPolicyDecision(
            preview_allowed=False,
            execute_allowed=False,
            reason_codes=reason_codes,
            required_role="operator",
            risk_tier="read_only",
        )

    if not remediation_action:
        reason_codes.append("no_remediation_action")
        return StructuredPolicyDecision(
            preview_allowed=False, execute_allowed=False, reason_codes=reason_codes
        )

    action_key = canonical_action_name(remediation_action.strip())
    defn = get_remediation_action(action_key)
    if defn is None:
        reason_codes.append("unknown_action")
        return StructuredPolicyDecision(
            preview_allowed=False, execute_allowed=False, reason_codes=reason_codes
        )

    pd = evaluate_action(action_key, operator_context.surface, pol)
    risk = pd.effective_risk
    preview_allowed = bool(pd.allowed) and operator_context.role in {"operator", "admin"}
    execute_allowed = False
    required_confirmation: str | None = defn.confirmation_phrase or None

    if not preview_allowed:
        reason_codes.extend([pd.reason, "classic_gate_denied"])
    else:
        reason_codes.extend([pd.reason] if pd.reason != "ok" else [])

    if defn.risk_level in {"forbidden", "high"}:
        reason_codes.append("execute_blocked_high_or_forbidden_tier")

    firewall_or_adapter_manual = (
        "firewall" in action_key.lower() or "adapter_disable" in action_key.lower()
    )
    if firewall_or_adapter_manual:
        reason_codes.append("firewall_or_adapter_manual_only")

    arbitrary = "arbitrary" in action_key
    if arbitrary:
        preview_allowed = False
        execute_allowed = False
        reason_codes.append("arbitrary_commands_forbidden")

    exec_candidate = (
        preview_allowed
        and operator_context.role == "admin"
        and pd.allowed
        and defn.api_execute_allowed
        and not defn.manual_only
        and risk not in {"high", "forbidden"}
    )
    if exec_candidate:
        execute_allowed = True
        reason_codes.append("eligible_pending_confirmation_and_route_gates")
        if required_confirmation:
            reason_codes.append("confirmation_phrase_required")
    elif operator_context.role != "admin" and preview_allowed and pd.allowed:
        reason_codes.append("operator_may_preview_only_live_requires_admin")

    if defn.manual_only and not arbitrary:
        execute_allowed = False
        reason_codes.append("manual_only_registry_entry")

    return StructuredPolicyDecision(
        execute_allowed=execute_allowed,
        preview_allowed=preview_allowed and not arbitrary,
        reason_codes=list(dict.fromkeys([c for c in reason_codes if c])),
        required_role="admin",
        required_confirmation=required_confirmation,
        risk_tier=risk,
    )

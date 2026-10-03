"""Conservative policy engine for proxy remediation actions.

Module responsibility:
    Map ``requested_action`` tokens plus entity risk/verification state to ``ALLOW``,
    ``PREVIEW``, or ``BLOCK`` outcomes.

Decision intent:
    Permit read-only diagnostics always; allow low-risk restore/disable only with acceptable
    verification; preview WinHTTP/firewall-adjacent actions; block destructive tokens.

Constraints:
    Action strings outside allow/preview/block catalogs default to ``PREVIEW`` or ``BLOCK``
    per implementation — treat unknown actions as untrusted.

Audit Notes:
    * A ``BLOCK`` decision should still be logged when operators attempt disallowed actions.
    * ``restore_proxy`` allowance depends on verification status — review ``verification_results``.
"""

from __future__ import annotations

from proxy_reasoning.models import PolicyAttributes, ProxyEntity, VerificationResult

ALLOW_READ_ONLY = frozenset(
    {
        "diagnose",
        "snapshot",
        "collect_signals",
        "validation_probe",
        "remediation_preview",
        "replay",
    },
)

ALLOW_LOW_RISK = frozenset(
    {
        "restore_proxy",
        "disable_proxy",
        "reset_wininet_proxy",
        "restore_known_good_proxy",
        "reset_user_proxy_flags",
    },
)

PREVIEW_ACTIONS = frozenset(
    {
        "clear_winhttp_proxy",
        "firewall_rule_cleanup_preview",
        "startup_persistence_review",
        "disable_user_proxy_preview",
    },
)

BLOCK_TOKENS = (
    "kill",
    "process_kill",
    "delete_cert",
    "disable_firewall",
    "reset_firewall",
    "arbitrary_shell",
    "registry_write",
    "delete_file",
    "adapter_disable",
)


def evaluate_proxy_policy(
    *,
    requested_action: str | None,
    entity: ProxyEntity,
    verification_results: list[VerificationResult],
    explicit_confirmation: bool = False,
) -> PolicyAttributes:
    """Map requested action and verification state to ALLOW / PREVIEW / BLOCK."""
    action = (requested_action or "").strip().lower()
    list(ALLOW_READ_ONLY)

    if any(token in action for token in BLOCK_TOKENS):
        return PolicyAttributes(
            decision="BLOCK",
            matched_rule="destructive_or_high_risk_token",
            reason=f"Action {requested_action!r} matches blocked policy tokens.",
            allowed_actions=sorted(ALLOW_READ_ONLY),
            blocked_actions=[requested_action or ""],
            requires_human_review=True,
        )

    if not action:
        return PolicyAttributes(
            decision="ALLOW",
            matched_rule="read_only_default",
            reason="No mutation requested; read-only diagnosis and preview permitted.",
            allowed_actions=sorted(ALLOW_READ_ONLY),
            blocked_actions=[],
            requires_human_review=False,
        )

    if action in ALLOW_READ_ONLY:
        return PolicyAttributes(
            decision="ALLOW",
            matched_rule="read_only_action",
            reason=f"Read-only action {action!r} is permitted.",
            allowed_actions=sorted(ALLOW_READ_ONLY | {action}),
            blocked_actions=[],
            requires_human_review=False,
        )

    confirmed_checks = [v for v in verification_results if v.status == "CONFIRMED"]
    high_risk = entity.trust_risk_attributes.classification in {
        "SUSPICIOUS_PROXY",
        "POSSIBLE_MITM_RISK",
    }

    if action in ALLOW_LOW_RISK:
        if high_risk and not explicit_confirmation:
            return PolicyAttributes(
                decision="PREVIEW",
                matched_rule="elevated_risk_requires_confirmation",
                reason="Elevated trust/risk classification requires preview and explicit confirmation.",
                allowed_actions=sorted(ALLOW_READ_ONLY | PREVIEW_ACTIONS),
                blocked_actions=[action],
                requires_human_review=True,
            )
        if not confirmed_checks and action not in {"snapshot", "diagnose"}:
            return PolicyAttributes(
                decision="PREVIEW",
                matched_rule="unverified_mutation",
                reason="Mutation requires preview until operational verification is CONFIRMED or operator confirms.",
                allowed_actions=sorted(ALLOW_READ_ONLY | PREVIEW_ACTIONS),
                blocked_actions=[],
                requires_human_review=True,
            )
        if explicit_confirmation or confirmed_checks:
            return PolicyAttributes(
                decision="ALLOW",
                matched_rule="low_risk_confirmed",
                reason="Low-risk allowlisted action with confirmation or CONFIRMED verification.",
                allowed_actions=sorted(ALLOW_READ_ONLY | ALLOW_LOW_RISK),
                blocked_actions=[],
                requires_human_review=not explicit_confirmation,
            )
        return PolicyAttributes(
            decision="PREVIEW",
            matched_rule="low_risk_preview",
            reason="Low-risk action remains in preview until operator confirmation.",
            allowed_actions=sorted(ALLOW_READ_ONLY | PREVIEW_ACTIONS | {action}),
            blocked_actions=[],
            requires_human_review=True,
        )

    if action in PREVIEW_ACTIONS:
        return PolicyAttributes(
            decision="PREVIEW",
            matched_rule="preview_only_action",
            reason=f"Action {action!r} is preview-gated by policy.",
            allowed_actions=sorted(ALLOW_READ_ONLY | PREVIEW_ACTIONS),
            blocked_actions=[],
            requires_human_review=True,
        )

    return PolicyAttributes(
        decision="BLOCK",
        matched_rule="unknown_action",
        reason=f"Action {requested_action!r} is not on the proxy remediation allowlist.",
        allowed_actions=sorted(ALLOW_READ_ONLY),
        blocked_actions=[requested_action or ""],
        requires_human_review=True,
    )

"""Policy package — classic registry gates + unified RBAC-aware remediation evaluation."""

from __future__ import annotations

from platform_core.policy.classic import (
    ACTION_REGISTRY,
    DEFAULT_POLICY,
    PolicyDecision,
    build_preview,
    evaluate_action,
    is_shell_injection,
    require_typed_confirmation,
    validate_confirmation_phrase,
)
from platform_core.policy.engine import (
    OperatorContext,
    SignalSnapshot,
    StructuredPolicyDecision,
    evaluate,
)

__all__ = [
    "ACTION_REGISTRY",
    "DEFAULT_POLICY",
    "PolicyDecision",
    "StructuredPolicyDecision",
    "OperatorContext",
    "SignalSnapshot",
    "build_preview",
    "evaluate",
    "evaluate_action",
    "is_shell_injection",
    "require_typed_confirmation",
    "validate_confirmation_phrase",
]

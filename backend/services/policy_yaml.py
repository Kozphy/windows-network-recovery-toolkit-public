"""Policy-as-code — YAML pack loader and evaluator."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "policy" / "enterprise_default.yaml"
)


@dataclass(frozen=True)
class YamlPolicyEvaluation:
    """Represent yaml policy evaluation data used by the toolkit.

    Attributes:
        classification: Field or variant describing classification evidence or state.
        decision: Field or variant describing decision evidence or state.
        severity: Field or variant describing severity evidence or state.
        allowed_actions: Field or variant describing allowed actions evidence or state.
        blocked_actions: Field or variant describing blocked actions evidence or state.
        requires_confirmation: Field or variant describing requires confirmation evidence or state.
        requires_human_approval: Field or variant describing requires human approval evidence or state.
        limitations: Field or variant describing limitations evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    classification: str
    decision: str
    severity: str
    allowed_actions: tuple[str, ...]
    blocked_actions: tuple[str, ...]
    requires_confirmation: bool
    requires_human_approval: bool
    limitations: tuple[str, ...]


def load_policy_yaml(path: Path | None = None) -> dict[str, Any]:
    """Load policy yaml.

    Args:
        path: Filesystem path used by the operation.

    Returns:
        The dict[str, Any] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    target = path or _DEFAULT_POLICY_PATH
    if not target.is_file():
        return _builtin_default_policy()
    return yaml.safe_load(target.read_text(encoding="utf-8")) or {}


def _builtin_default_policy() -> dict[str, Any]:
    return {
        "schema_version": "enterprise_policy.v1",
        "default_mode": "read_only",
        "classification_rules": {
            "UNKNOWN_LOCAL_PROXY": {
                "decision": "ALERT",
                "severity": "HIGH",
                "allowed_actions": ["observe", "preview_disable", "export_report"],
                "blocked_actions": ["kill_process", "registry_mutation"],
                "requires_confirmation": True,
            },
            "SUSPICIOUS_PROXY": {
                "decision": "BLOCK_RECOMMENDED",
                "severity": "CRITICAL",
                "requires_confirmation": True,
            },
            "POSSIBLE_MITM_RISK": {
                "decision": "ESCALATE_REVIEW",
                "severity": "CRITICAL",
                "requires_human_approval": True,
            },
        },
        "safety": {
            "never_kill_process_automatically": True,
            "never_reset_network_automatically": True,
            "registry_mutation_requires_typed_confirmation": True,
            "default_mode": "read_only",
        },
    }


def evaluate_yaml_policy(
    classification: str,
    *,
    policy_doc: dict[str, Any] | None = None,
    requested_action: str = "observe",
) -> YamlPolicyEvaluation:
    """Evaluate tenant policy pack for a classification label."""
    doc = policy_doc or load_policy_yaml()
    rules = doc.get("classification_rules") or {}
    rule = rules.get(classification.upper()) or rules.get(classification) or {}
    safety = doc.get("safety") or {}

    decision = str(rule.get("decision") or "OBSERVE")
    severity = str(rule.get("severity") or "MEDIUM")
    allowed = tuple(str(a) for a in (rule.get("allowed_actions") or ["observe", "export_report"]))
    blocked = tuple(str(b) for b in (rule.get("blocked_actions") or []))

    if safety.get("never_kill_process_automatically") and requested_action in {
        "kill_process",
        "terminate",
    }:
        blocked = blocked + (requested_action,)

    requires_confirmation = bool(rule.get("requires_confirmation", False))
    requires_human = bool(
        rule.get("requires_human_approval", False)
        or decision in {"ESCALATE_REVIEW", "BLOCK_RECOMMENDED"}
        or severity == "CRITICAL"
    )

    limitations = (
        "Policy-as-code output — not malware verdict or autonomous authorization.",
        "Observation is not proof; correlation is not causation.",
    )
    if safety.get("default_mode") == "read_only":
        limitations = limitations + ("Default mode is read-only — no autonomous remediation.",)

    return YamlPolicyEvaluation(
        classification=classification.upper(),
        decision=decision,
        severity=severity,
        allowed_actions=allowed,
        blocked_actions=blocked,
        requires_confirmation=requires_confirmation,
        requires_human_approval=requires_human,
        limitations=limitations,
    )

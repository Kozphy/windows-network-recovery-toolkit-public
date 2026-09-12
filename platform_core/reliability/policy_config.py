"""Configurable policy evaluation — ALLOW / PREVIEW / BLOCK."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from .models import PolicyOutcome, RankedHypothesis

PolicyOutcomeType = Literal["ALLOW", "PREVIEW", "BLOCK"]


@dataclass
class PolicyRule:
    """Represent PolicyRule data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    rule_id: str
    outcome: PolicyOutcomeType
    min_confidence: float = 0.0
    requires_proof_tier: bool = False
    blocked_actions: tuple[str, ...] = ()
    reason: str = ""


@dataclass
class PolicyConfig:
    """Loadable policy configuration."""

    default_outcome: PolicyOutcomeType = "PREVIEW"
    safe_mode: bool = True
    rules: list[PolicyRule] = field(default_factory=list)

    @classmethod
    def production_defaults(cls) -> PolicyConfig:
        """Provide production defaults behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return cls(
            default_outcome="PREVIEW",
            safe_mode=True,
            rules=[
                PolicyRule(
                    rule_id="destructive_always_block",
                    outcome="BLOCK",
                    blocked_actions=("firewall_reset", "adapter_disable", "process_kill_arbitrary"),
                    reason="Destructive actions are manual-only.",
                ),
                PolicyRule(
                    rule_id="proof_and_confirmation_allow",
                    outcome="ALLOW",
                    min_confidence=0.85,
                    requires_proof_tier=True,
                    reason="Safe-tier allow only with proof and explicit confirmation.",
                ),
                PolicyRule(
                    rule_id="high_impact_preview",
                    outcome="PREVIEW",
                    min_confidence=0.70,
                    reason="High ordinal confidence without proof remains preview-only.",
                ),
            ],
        )

    @classmethod
    def from_yaml_path(cls, path: Path) -> PolicyConfig:
        """Provide from yaml path behavior for toolkit workflows.

        Args:
            path: Value supplied by the caller for path.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        if not path.is_file():
            return cls.production_defaults()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return cls.production_defaults()
        return cls._parse_minimal_yaml(text)

    @classmethod
    def _parse_minimal_yaml(cls, text: str) -> PolicyConfig:
        """Minimal parser without PyYAML dependency."""
        cfg = cls.production_defaults()
        if "safe_mode: false" in text.lower():
            cfg.safe_mode = False
        if 'default_outcome: "ALLOW"' in text or "default_outcome: ALLOW" in text:
            cfg.default_outcome = "ALLOW"
        return cfg


def evaluate_platform_policy(
    *,
    hypothesis: RankedHypothesis | None,
    policy: PolicyConfig | None = None,
    requested_action: str | None = None,
    has_proof_tier: bool = False,
    explicit_confirmation: bool = False,
) -> tuple[PolicyOutcome, list[str]]:
    """Evaluate policy; return outcome and reason codes."""
    cfg = policy or PolicyConfig.production_defaults()
    codes: list[str] = []

    if requested_action:
        for rule in cfg.rules:
            if requested_action in rule.blocked_actions:
                codes.append(f"blocked_action:{rule.rule_id}")
                return "BLOCK", codes

    if cfg.safe_mode:
        codes.append("safe_mode_default_preview")

    conf = hypothesis.confidence if hypothesis else 0.0
    if hypothesis and hypothesis.category == "potential_malware" and not has_proof_tier:
        codes.append("malware_hypothesis_requires_proof_tier")
        return "PREVIEW", codes

    for rule in cfg.rules:
        if rule.outcome == "ALLOW" and conf >= rule.min_confidence:
            if rule.requires_proof_tier and not has_proof_tier:
                codes.append("allow_requires_proof_tier")
                continue
            if rule.requires_proof_tier and not explicit_confirmation:
                codes.append("allow_requires_explicit_confirmation")
                return "PREVIEW", codes
            codes.append(f"matched_rule:{rule.rule_id}")
            return "ALLOW", codes

    if conf >= 0.70 and not has_proof_tier:
        codes.append("unproven_high_confidence_is_not_execute_authority")
        return "PREVIEW", codes

    return cfg.default_outcome, codes

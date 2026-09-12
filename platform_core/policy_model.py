"""Canonical endpoint reliability policy decisions."""

from __future__ import annotations

from typing import Any, Literal

from platform_core.evidence_model import EvidenceLevel, evidence_rank

PolicyDecision = Literal[
    "ALLOW_OBSERVE",
    "PREVIEW_ONLY",
    "REQUIRE_TYPED_CONFIRMATION",
    "BLOCK_DESTRUCTIVE",
    "BLOCK_LOW_CONFIDENCE",
    "CORRELATION_ONLY_ALERT",
]

_DESTRUCTIVE = frozenset(
    {"kill_process", "process_kill", "reset_firewall", "disable_adapter", "adapter_disable", "arbitrary_shell"}
)


def evaluate_endpoint_policy(
    *,
    evidence_level: str | EvidenceLevel,
    confidence_ordinal: float = 0.5,
    requested_action: str | None = None,
    external_proxy: bool = False,
    known_dev_tool: bool = False,
    healthy_baseline: bool = False,
) -> dict[str, Any]:
    """Map evidence + context to policy gate. Policy permission ≠ safety guarantee."""
    level = str(evidence_level).upper()
    action = (requested_action or "").lower()

    if healthy_baseline:
        return _row("ALLOW_OBSERVE", [], False, False)
    if any(tok in action for tok in _DESTRUCTIVE):
        return _row("BLOCK_DESTRUCTIVE", ["Destructive token blocked."], False, False)
    if confidence_ordinal < 0.4:
        return _row("BLOCK_LOW_CONFIDENCE", ["Ordinal confidence below threshold."], False, False)

    if known_dev_tool and evidence_rank(level) <= evidence_rank("CORRELATED"):
        return _row("ALLOW_OBSERVE", ["Known dev tooling — log and observe."], False, False)

    if evidence_rank(level) <= evidence_rank("CORRELATED"):
        reasons = ["Correlation-only evidence — alert without execute."]
        if external_proxy:
            return _row("REQUIRE_TYPED_CONFIRMATION", reasons + ["External proxy."], False, True)
        return _row("CORRELATION_ONLY_ALERT", reasons, False, True)

    if evidence_rank(level) >= evidence_rank("PROVEN_REGISTRY_WRITER"):
        return _row(
            "REQUIRE_TYPED_CONFIRMATION",
            ["Writer proof — preview allowed; execute needs typed confirmation."],
            False,
            True,
        )

    return _row("PREVIEW_ONLY", ["Default preview-only gate."], False, True)


def _row(decision: PolicyDecision, reasons: list[str], execute: bool, preview: bool) -> dict[str, Any]:
    return {
        "decision": decision,
        "execute_allowed": execute,
        "preview_allowed": preview,
        "reasons": reasons,
        "safety_note": "API execute defaults to dry_run=true; policy is not a safety guarantee.",
    }

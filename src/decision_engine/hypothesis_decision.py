"""Backward compatibility shim; canonical implementation: :mod:`src.policy.hypothesis_gates`."""

from __future__ import annotations

from ..policy.hypothesis_gates import (
    HYPOTHESIS_DISPLAY_NAME,
    PROOF_LOCALHOST_PROXY_HYPOTHESES,
    HypothesisDecisionRow,
    PolicyDecision,
    build_hypothesis_decisions,
    build_why,
    decide_policy,
    hypothesis_display_name,
    proof_status_token,
)

__all__ = [
    "HYPOTHESIS_DISPLAY_NAME",
    "PROOF_LOCALHOST_PROXY_HYPOTHESES",
    "HypothesisDecisionRow",
    "PolicyDecision",
    "build_hypothesis_decisions",
    "build_why",
    "decide_policy",
    "hypothesis_display_name",
    "proof_status_token",
]

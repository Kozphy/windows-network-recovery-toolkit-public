"""Hypothesis engine (v2 live ranking + legacy v1 FeatureVector buckets) and derived copy.

Canonical keys and risk ordinals feed :mod:`src.policy`; this package does not perform
policy gating or proof probes.
"""

from __future__ import annotations

from .keys import ALL_HYPOTHESES, HypothesisKey
from .live_scoring import LiveHypothesisScore, ranked_dicts, score_live_snapshot
from .risk import default_impacts_table, hypothesis_impact, hypothesis_risk_score
from .v1_scoring import (
    ALL_CAUSES,
    CauseScore,
    DecisionResult,
    RootCauseKey,
    explain_primary,
    score_root_causes,
)

__all__ = [
    "ALL_CAUSES",
    "ALL_HYPOTHESES",
    "CauseScore",
    "DecisionResult",
    "HypothesisKey",
    "LiveHypothesisScore",
    "RootCauseKey",
    "default_impacts_table",
    "explain_primary",
    "hypothesis_impact",
    "hypothesis_risk_score",
    "ranked_dicts",
    "score_live_snapshot",
    "score_root_causes",
]

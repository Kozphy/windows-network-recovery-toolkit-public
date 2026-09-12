"""Backward compatibility shim; canonical implementation: :mod:`src.hypothesis.v1_scoring`."""

from __future__ import annotations

from ..hypothesis.v1_scoring import (
    ALL_CAUSES,
    CauseScore,
    DecisionResult,
    RootCauseKey,
    explain_primary,
    score_root_causes,
)

__all__ = [
    "ALL_CAUSES",
    "CauseScore",
    "DecisionResult",
    "RootCauseKey",
    "explain_primary",
    "score_root_causes",
]

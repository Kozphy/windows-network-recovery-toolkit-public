"""Hypothesis package interfaces for evidence-based scenario analysis.

Module responsibility:
    Expose package-level interfaces without performing runtime work.

System placement:
    Imported by platform modules that need the package namespace.

Key invariants:
    Importing this package must not collect evidence or mutate state.

Side effects:
    None.
"""

from src.platform_core.hypothesis.engine import build_hypothesis, evaluate_multievidence
from src.platform_core.hypothesis.models import (
    HypothesisEngineResult,
    HypothesisEvaluation,
    MultievidenceInput,
)
from src.platform_core.hypothesis.multievidence_engine import (
    evaluate_hypotheses,
    multievidence_from_fixture,
)

__all__ = [
    "HypothesisEngineResult",
    "HypothesisEvaluation",
    "MultievidenceInput",
    "build_hypothesis",
    "evaluate_hypotheses",
    "evaluate_multievidence",
    "multievidence_from_fixture",
]

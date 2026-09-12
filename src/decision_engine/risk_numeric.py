"""Backward compatibility shim; canonical implementation: :mod:`src.hypothesis.risk`."""

from __future__ import annotations

from ..hypothesis.risk import default_impacts_table, hypothesis_impact, hypothesis_risk_score

__all__ = ["default_impacts_table", "hypothesis_impact", "hypothesis_risk_score"]

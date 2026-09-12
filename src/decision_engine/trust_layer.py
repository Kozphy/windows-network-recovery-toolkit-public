"""Backward compatibility shim; canonical implementation: :mod:`src.observation.trust`."""

from __future__ import annotations

from ..observation.trust import SignalConflict, TrustAssessment, assess_trust

__all__ = ["SignalConflict", "TrustAssessment", "assess_trust"]

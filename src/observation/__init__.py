"""Observation layer: trust aggregates over snapshots and adversarial heuristic hints.

This package sits downstream of collectors and upstream of hypothesis ranking and policy.
Boundary: operates on frozen :class:`~src.core.models.LiveNetworkSnapshot` (and proof
summaries supplied by callers), never on raw subprocess buffers.
"""

from __future__ import annotations

from .adversarial import adversarial_hints
from .trust import SignalConflict, TrustAssessment, assess_trust

__all__ = [
    "SignalConflict",
    "TrustAssessment",
    "adversarial_hints",
    "assess_trust",
]

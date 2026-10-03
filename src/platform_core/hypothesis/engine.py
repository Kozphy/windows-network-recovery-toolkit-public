"""Hypothesis generation from evidence bundle."""

from __future__ import annotations

import uuid

from src.platform_core.contracts import EvidenceBundle, Hypothesis
from src.platform_core.hypothesis.models import MultievidenceInput
from src.platform_core.hypothesis.multievidence_engine import evaluate_hypotheses


def build_hypothesis(
    bundle: EvidenceBundle, *, incident_type: str, title: str, explanation: str
) -> Hypothesis:
    """Build hypothesis.

    Args:
        bundle: bundle supplied by the caller.
        incident_type: incident type supplied by the caller.
        title: title supplied by the caller.
        explanation: explanation supplied by the caller.

    Returns:
        The computed `Hypothesis` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return Hypothesis(
        hypothesis_id=f"hyp-{uuid.uuid4().hex[:12]}",
        event_id=bundle.incident_id,
        title=title,
        explanation=explanation,
        confidence=0.7,
        supporting_evidence_ids=[i.evidence_id for i in bundle.items],
        incident_type=incident_type,
    )


def evaluate_multievidence(data: MultievidenceInput):
    """Run multievidence hypothesis engine — see multievidence_engine.evaluate_hypotheses."""
    return evaluate_hypotheses(data)

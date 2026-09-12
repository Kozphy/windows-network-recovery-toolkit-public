"""Decision engine — assembles a Decision from a hypothesis and evidence bundle.

Module responsibility:
    Provides ``build_decision``, the single factory function that constructs a
    typed ``Decision`` dataclass from an ``EvidenceBundle``, a ``Hypothesis``, and
    caller-supplied risk metadata.  Decision IDs are generated as unique
    hex-prefixed UUIDs to support traceability across audit records.

System placement:
    Called by CLI command handlers (e.g. ``diagnose``) and the platform API after
    classification and policy evaluation are complete.  The returned ``Decision``
    is passed to ``append_audit`` for governance traceability.

Key invariants:
    - ``decision_id`` is always a fresh UUID; it is never reused or recycled.
    - ``trace_id`` is set to ``bundle.incident_id`` by convention; downstream
      audit consumers may rely on this for incident-level log correlation.
    - Confidence and evidence tier are copied directly from the hypothesis and
      bundle; this function does not re-evaluate or modify them.

Side effects:
    None.  Pure factory; no file, network, or registry access.

Failure modes:
    Raises ``ImportError`` if ``platform_core.models`` is not importable (inline
    import inside ``build_decision``); this is a latent structural dependency that
    should be resolved to a top-of-file import.
"""

from __future__ import annotations

import uuid

from src.platform_core.contracts import Decision, EvidenceBundle, Hypothesis


def build_decision(
    bundle: EvidenceBundle,
    hypothesis: Hypothesis,
    *,
    recommended_action: str,
    risk_level: str = "medium",
    requires_human_review: bool = False,
) -> Decision:
    """Build decision.

    Args:
        bundle: bundle supplied by the caller.
        hypothesis: hypothesis supplied by the caller.
        recommended_action: recommended action supplied by the caller.
        risk_level: risk level supplied by the caller.
        requires_human_review: requires human review supplied by the caller.

    Returns:
        The computed `Decision` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    from platform_core.models import utc_now_iso

    return Decision(
        decision_id=f"dec-{uuid.uuid4().hex[:12]}",
        incident_id=bundle.incident_id,
        trace_id=bundle.incident_id,
        timestamp_utc=utc_now_iso(),
        incident_type=hypothesis.incident_type,
        recommended_action=recommended_action,
        confidence=hypothesis.confidence,
        risk_level=risk_level,  # type: ignore[arg-type]
        evidence_tier=bundle.tier,
        evidence_refs=hypothesis.supporting_evidence_ids,
        reasoning=hypothesis.explanation,
        requires_human_review=requires_human_review,
    )

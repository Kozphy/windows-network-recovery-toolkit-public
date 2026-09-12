"""Explainable ordinal confidence scoring for Technology Risk evidence.

Module responsibility:
    Translate qualitative rank labels (``low`` / ``medium`` / ``high``) and
    evidence tiers into a bounded float score, and produce human-readable
    explanations that accompany every decision record.

System placement:
    Called by ``hypothesis_engine.evaluate_incident`` and by any audit or
    report renderer that needs a printable confidence statement.

Key invariants:
    * Scores are capped at 0.98 — a score of 1.0 is never emitted, preserving
      epistemic humility: observation ≠ certainty.
    * Evidence-tier bonuses are additive adjustments, not statistical
      likelihoods; they model analytic confidence, not probability.
    * The ``explain_confidence`` narrative always appends the disclaimer
      "Confidence is not certainty; correlation is not causation."

Side effects:
    None — both functions are pure and stateless.

Failure modes:
    Unknown ``rank`` or ``evidence_level`` keys are silently treated as their
    respective defaults (0.5 base / 0.0 bonus); no exception is raised.
"""

from __future__ import annotations

_RANK_TO_FLOAT = {"low": 0.45, "medium": 0.72, "high": 0.88}
_EVIDENCE_BONUS = {
    "OBSERVED_ONLY": 0.0,
    "CORRELATED": 0.05,
    "PROVEN_REGISTRY_WRITER": 0.12,
    "PROVEN_NETWORK_IMPACT": 0.15,
    "FINAL_CAUSATION": 0.18,
}


def ordinal_confidence(rank: str, *, evidence_level: str | None = None) -> float:
    """Compute a bounded confidence score from an ordinal rank and optional evidence tier.

    Args:
        rank: Qualitative rank string — one of ``"low"``, ``"medium"``, or
            ``"high"``.  Unrecognised values default to a base of 0.5.
        evidence_level: Optional evidence-tier key from ``_EVIDENCE_BONUS``
            (e.g. ``"CORRELATED"``, ``"PROVEN_REGISTRY_WRITER"``).  ``None``
            applies no bonus.

    Returns:
        Float in ``[0.0, 0.98]``.  Never returns 1.0; scores are ordinal
        analytic confidence, not calibrated probabilities.
    """
    base = _RANK_TO_FLOAT.get(str(rank).lower(), 0.5)
    bonus = _EVIDENCE_BONUS.get(str(evidence_level or "").upper(), 0.0)
    return min(0.98, base + bonus)


def explain_confidence(
    rank: str, *, evidence_level: str | None = None, supporting: list[str] | None = None
) -> str:
    """Build a human-readable confidence explanation for audit and decision records.

    Args:
        rank: Ordinal rank label (``"low"``, ``"medium"``, ``"high"``).
        evidence_level: Optional evidence-tier key; included in the narrative
            when provided.
        supporting: Optional list of supporting signal names surfaced in the
            explanation text.

    Returns:
        A single-string narrative that states the numeric score, tier, any
        supporting signals, and the standard epistemic disclaimer.  Always
        ends with "Confidence is not certainty; correlation is not causation."
    """
    score = ordinal_confidence(rank, evidence_level=evidence_level)
    parts = [f"Ordinal confidence {score:.2f} derived from rank={rank!r}."]
    if evidence_level:
        parts.append(f"Evidence tier {evidence_level} adjusts score (not calibrated probability).")
    if supporting:
        parts.append(f"Supporting signals: {', '.join(supporting)}.")
    parts.append("Confidence is not certainty; correlation is not causation.")
    return " ".join(parts)

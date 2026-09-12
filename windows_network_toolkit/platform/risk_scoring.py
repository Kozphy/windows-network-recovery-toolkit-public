"""Risk scoring from classification and proof results.

Module responsibility:
    Compute a numeric risk score and ordinal risk label from a
    ``ClassificationResult`` and an optional ``ProofResult``.  Provides a
    lightweight, rule-based alternative to ML-derived risk models.

System placement:
    Called by ``platform.decision_engine.decide`` to populate the
    ``"risk_assessment"`` field of the decision response.

Key invariants:
    * Severity is mapped to an integer weight (``info=1``, ``low=2``,
      ``medium=3``, ``high=4``); the final score is ``confidence × weight``,
      capped at 4.0.
    * Specific high-risk classifications (``SUSPICIOUS_PROXY``,
      ``POSSIBLE_MITM_RISK``, ``REVERTER_SUSPECTED``) override the label to
      ``"high"`` regardless of the numeric score.
    * A ``"supported"`` proof conclusion adds 0.5 to the score (capped at
      4.0), reflecting increased analytic confidence.
    * Risk score is an analytic aid, not a probability; risk level drives
      operator priority, not autonomous action.

Side effects:
    None — pure function.
"""

from __future__ import annotations

from windows_network_toolkit.models import ClassificationResult, ProofResult


def score_risk(
    classification: ClassificationResult,
    proof: ProofResult | None = None,
) -> dict[str, object]:
    """Compute a rule-based risk score from classification and optional proof.

    Args:
        classification: The current endpoint ``ClassificationResult``.
        proof: Optional ``ProofResult``; when ``conclusion_status`` is
            ``"supported"``, 0.5 is added to the numeric score (capped at
            4.0).

    Returns:
        Dict with keys:

        * ``"risk_level"`` — ordinal label (``"info"`` / ``"low"`` /
          ``"medium"`` / ``"high"``).  Always ``"high"`` for the three
          highest-risk classifications.
        * ``"score"`` — numeric score (float, rounded to 2 dp) in
          ``[0.0, 4.0]``.
        * ``"primary_classification"`` — the classification label.
        * ``"proof_status"`` — ``proof.conclusion_status`` or
          ``"not_run"`` when no proof was supplied.
    """
    severity_map = {"info": 1, "low": 2, "medium": 3, "high": 4}
    base = severity_map.get(classification.severity, 2)
    score = classification.confidence * base
    if proof and proof.conclusion_status == "supported":
        score = min(4.0, score + 0.5)
    label = classification.severity
    if classification.primary_classification in {
        "SUSPICIOUS_PROXY",
        "POSSIBLE_MITM_RISK",
        "REVERTER_SUSPECTED",
    }:
        label = "high"
    return {
        "risk_level": label,
        "score": round(score, 2),
        "primary_classification": classification.primary_classification,
        "proof_status": proof.conclusion_status if proof else "not_run",
    }

"""Ordinal confidence calculation — heuristic rank, not probability."""

from __future__ import annotations

from src.platform_core.hypothesis.models import ConfidenceRank, EvidenceRef, EvidenceTierName

_RANK_BASE: dict[str, float] = {"low": 0.45, "medium": 0.72, "high": 0.88}
_TIER_BONUS: dict[str, float] = {
    "OBSERVED_ONLY": 0.0,
    "CORRELATED": 0.04,
    "PROVEN_REGISTRY_WRITER": 0.08,
    "PROVEN_NETWORK_IMPACT": 0.10,
    "FINAL_CAUSATION": 0.12,
}
_MAX_SCORE = 0.98


def rank_from_score(score: float) -> ConfidenceRank:
    """Return rank from score.

    Args:
        score: score supplied by the caller.

    Returns:
        The computed `ConfidenceRank` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    if score >= 0.80:
        return "high"
    if score >= 0.58:
        return "medium"
    return "low"


def format_confidence_display(score: float) -> str:
    """Format confidence display.

    Args:
        score: score supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return f"ordinal {score:.2f} (heuristic rank, not probability or certainty)"


def compute_confidence(
    *,
    base_rank: str,
    supporting: list[EvidenceRef],
    required_matched: int,
    required_total: int,
    proof_matched: int,
    missing_count: int,
    cross_domain_corroboration: bool,
) -> tuple[float, ConfidenceRank, str]:
    """Return (score, rank, explanation)."""
    base = _RANK_BASE.get(base_rank.lower(), 0.5)

    tier_bonus = 0.0
    if supporting:
        max_tier = max(_TIER_BONUS.get(e.tier, 0.0) for e in supporting)
        tier_bonus = max_tier

    coverage = required_matched / required_total if required_total else 0.5
    coverage_bonus = 0.06 * coverage

    proof_bonus = 0.05 * proof_matched
    cross_bonus = 0.04 if cross_domain_corroboration else 0.0
    missing_penalty = 0.06 * missing_count

    raw = base + tier_bonus + coverage_bonus + proof_bonus + cross_bonus - missing_penalty
    score = max(0.10, min(_MAX_SCORE, round(raw, 3)))
    rank = rank_from_score(score)

    parts = [
        f"Base rank {base_rank!r} → {base:.2f}.",
        f"Required signal coverage {required_matched}/{required_total}.",
    ]
    if proof_matched:
        parts.append(f"Proof-tier signals matched: {proof_matched}.")
    if cross_domain_corroboration:
        parts.append("Cross-domain corroboration (registry + network/process).")
    if missing_count:
        parts.append(f"Penalty for {missing_count} missing evidence item(s).")
    if tier_bonus:
        parts.append(f"Evidence tier bonus +{tier_bonus:.2f} (max tier among supporting).")
    parts.append("Score is ordinal heuristic — not calibrated probability.")

    return score, rank, " ".join(parts)


def tier_is_proof(tier: EvidenceTierName) -> bool:
    """Return tier is proof.

    Args:
        tier: tier supplied by the caller.

    Returns:
        The computed `bool` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return tier in {
        "PROVEN_REGISTRY_WRITER",
        "PROVEN_NETWORK_IMPACT",
        "FINAL_CAUSATION",
    }

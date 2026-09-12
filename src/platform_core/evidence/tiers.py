"""Canonical evidence tier vocabulary."""

from __future__ import annotations

from typing import Literal

EvidenceTier = Literal[
    "OBSERVED_ONLY",
    "CORRELATED",
    "PROVEN_REGISTRY_WRITER",
    "PROVEN_NETWORK_IMPACT",
    "FINAL_CAUSATION",
]

EVIDENCE_TIER_ORDER: tuple[EvidenceTier, ...] = (
    "OBSERVED_ONLY",
    "CORRELATED",
    "PROVEN_REGISTRY_WRITER",
    "PROVEN_NETWORK_IMPACT",
    "FINAL_CAUSATION",
)

_RANK = {t: i for i, t in enumerate(EVIDENCE_TIER_ORDER)}

# Legacy aliases (shim imports, older tests, proxy_guard vocabulary)
_LEGACY_MAP: dict[str, EvidenceTier] = {
    "OBSERVED_ONLY": "OBSERVED_ONLY",
    "CORRELATED": "CORRELATED",
    "CORRELATED_PROCESS": "CORRELATED",
    "PROVEN_REGISTRY_WRITER": "PROVEN_REGISTRY_WRITER",
    "PROVEN_NETWORK_IMPACT": "PROVEN_NETWORK_IMPACT",
    "PATH_VALIDATED": "PROVEN_NETWORK_IMPACT",
    "FINAL_CAUSATION": "FINAL_CAUSATION",
}


def tier_rank(tier: str | EvidenceTier) -> int:
    """Return tier rank.

    Args:
        tier: tier supplied by the caller.

    Returns:
        The computed `int` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    raw = str(tier).upper()
    normalized: EvidenceTier | str = _LEGACY_MAP.get(raw, raw)
    if normalized in _RANK:
        return _RANK[normalized]
    return -1


def normalize_tier(tier: str) -> EvidenceTier:
    """Normalize tier.

    Args:
        tier: tier supplied by the caller.

    Returns:
        The computed `EvidenceTier` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    key = str(tier).upper()
    if key in _LEGACY_MAP:
        return _LEGACY_MAP[key]
    for known in EVIDENCE_TIER_ORDER:
        if known == key:
            return known
    return "OBSERVED_ONLY"

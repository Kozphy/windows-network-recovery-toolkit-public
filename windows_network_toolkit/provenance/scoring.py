"""Score operator country separately from infrastructure geography.

Module responsibility:
    Aggregate operator-facing signals into a country hypothesis and confidence;
    record infrastructure countries only as mismatch/context.

System placement:
    After collectors; before policy.

Key invariants:
    * Infrastructure signals (``ip_geo``, ``asn_country``) never set
      ``operator_country``.
    * Confidence uses support / (support + uncertainty) with uncertainty=0.1.
    * Empty operator support → INSUFFICIENT / empty country.

Side effects:
    None.
"""

from __future__ import annotations

from windows_network_toolkit.provenance.models import (
    ConfidenceBand,
    InfrastructureMismatch,
    ProvenanceScore,
    ProvenanceSignal,
    SignalKind,
)

UNCERTAINTY = 0.1


def _band(confidence: float, *, has_support: bool) -> ConfidenceBand:
    if not has_support or confidence <= 0.0:
        return ConfidenceBand.INSUFFICIENT
    if confidence >= 0.85:
        return ConfidenceBand.HIGH
    if confidence >= 0.55:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW


def score_provenance(signals: list[ProvenanceSignal]) -> ProvenanceScore:
    """Score operator country from operator signals only.

    Args:
        signals: Collected provenance signals.

    Returns:
        ``ProvenanceScore`` with operator country, confidence, infra list,
        and informational mismatches when hosting geography differs.
    """
    support: dict[str, float] = {}
    for sig in signals:
        if sig.kind != SignalKind.OPERATOR:
            continue
        country = (sig.country or "").upper()
        if not country or sig.weight <= 0:
            continue
        support[country] = support.get(country, 0.0) + float(sig.weight)

    infra: list[str] = []
    for sig in signals:
        if sig.kind != SignalKind.INFRASTRUCTURE:
            continue
        country = (sig.country or "").upper()
        if country and country not in infra:
            infra.append(country)

    if not support:
        return ProvenanceScore(
            operator_country="",
            confidence=0.0,
            confidence_band=ConfidenceBand.INSUFFICIENT,
            support_by_country={},
            infrastructure_countries=infra,
            mismatches=[],
            signals=list(signals),
        )

    operator_country = max(support.items(), key=lambda kv: (kv[1], kv[0]))[0]
    raw_support = support[operator_country]
    confidence = round(raw_support / (raw_support + UNCERTAINTY), 3)
    band = _band(confidence, has_support=True)

    mismatches: list[InfrastructureMismatch] = []
    differing = [c for c in infra if c != operator_country]
    if differing:
        mismatches.append(
            InfrastructureMismatch(
                operator_country=operator_country,
                infrastructure_countries=differing,
                severity="informational",
                detail=(
                    f"Infrastructure geography {', '.join(differing)} differs from "
                    f"operator-country hypothesis {operator_country}; hosting/CDN "
                    "location does not determine operator country."
                ),
            )
        )

    return ProvenanceScore(
        operator_country=operator_country,
        confidence=confidence,
        confidence_band=band,
        support_by_country={k: round(v, 3) for k, v in sorted(support.items())},
        infrastructure_countries=infra,
        mismatches=mismatches,
        signals=list(signals),
    )

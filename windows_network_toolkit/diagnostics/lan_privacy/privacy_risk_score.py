"""Transparent Privacy Risk Score for home/SOHO LAN analytics.

Module responsibility:
    Compute capped numeric score, risk level, and component breakdown from
    classification, devices, observations, and optional router correlation.

System placement:
    Invoked by ``lan_privacy.runner`` risk pipeline and ``lan-risk-score`` CLI.

Key invariants:
    * Score components are capped and explainable — not a malware detection engine.
    * Evidence tier reflects highest present source (host vs router vs insufficient).
    * ``LAN_LIMITATIONS`` copied into every result for safe consumer wording.

Side effects:
    * None — deterministic scoring over supplied dicts.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from .models import LAN_LIMITATIONS, EvidenceSource, LanClassification

# Component caps per plan
CAP_BREADTH = 20
CAP_FREQUENCY = 20
CAP_UNKNOWN_VENDOR = 15
CAP_EXTERNAL_DOMAIN = 25
CAP_RECURRENCE = 20
CAP_DISCOUNT = 30

# External domain risk weights (observation only — not malware verdict)
TELEMETRY_DOMAIN_HINTS = frozenset(
    {
        "metrics.",
        "analytics.",
        "tracking.",
        "telemetry.",
        "adservice.",
        "doubleclick.",
    }
)


@dataclass
class PrivacyRiskScoreResult:
    """Output of ``compute_privacy_risk_score``.

    Attributes:
        numeric_score: Capped score in [0.0, 100.0].
        risk_level: ``"LOW"``, ``"MEDIUM"``, or ``"HIGH"`` based on thresholds.
        evidence_tier: Highest evidence tier present (``T0_OBSERVATION``,
            ``T1_STATE_EVIDENCE``, or ``T2_RUNTIME_EVIDENCE``).
        components: Per-component score and rationale dicts for transparency.
        explanation: Plain-text governance summary — not a security verdict.
        limitations: ``LAN_LIMITATIONS`` plus any source-specific caveats.
        evidence_sources_present: Sorted list of ``EvidenceSource`` values seen.
        human_review_recommended: ``True`` when level is HIGH or classification
            indicates broad/lateral probing.
    """

    numeric_score: float
    risk_level: str
    evidence_tier: str
    components: dict[str, Any]
    explanation: str
    limitations: list[str] = field(default_factory=list)
    evidence_sources_present: list[str] = field(default_factory=list)
    human_review_recommended: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON serialization."""
        return asdict(self)


def _risk_level(score: float) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def _evidence_tier(sources: set[str], event_count: int) -> str:
    if EvidenceSource.ROUTER_LEVEL_EVIDENCE.value in sources:
        return "T2_RUNTIME_EVIDENCE"
    if event_count >= 5:
        return "T1_STATE_EVIDENCE"
    return "T0_OBSERVATION"


def _discovery_breadth(observations: list[dict[str, Any]]) -> tuple[float, str]:
    targets: set[str] = set()
    for o in observations:
        t = o.get("target_ip") or o.get("domain") or ""
        if t:
            targets.add(t)
        src = o.get("source_ip", "")
        if src:
            targets.add(src)
    breadth = len(targets)
    score = min(CAP_BREADTH, breadth * 2.5)
    return score, f"Unique targets/sources observed: {breadth}"


def _probe_frequency(observations: list[dict[str, Any]]) -> tuple[float, str]:
    count = len(observations)
    score = min(CAP_FREQUENCY, count * 1.5)
    return score, f"Total probe/discovery events: {count}"


def _unknown_vendor_weight(devices: list[dict[str, Any]]) -> tuple[float, str]:
    unknown = sum(1 for d in devices if "unknown_vendor" in (d.get("flags") or []))
    if not devices:
        return 0.0, "No device inventory available"
    ratio = unknown / max(len(devices), 1)
    score = min(CAP_UNKNOWN_VENDOR, ratio * CAP_UNKNOWN_VENDOR * 1.5)
    return score, f"Unknown-vendor devices: {unknown}/{len(devices)}"


def _external_domain_risk(router_events: list[dict[str, Any]]) -> tuple[float, str]:
    dns_events = [e for e in router_events if e.get("event_type") == "dns" or e.get("domain")]
    if not dns_events:
        return 0.0, "No router DNS evidence imported"
    risky = 0
    domains: list[str] = []
    for e in dns_events:
        domain = (e.get("domain") or e.get("query") or "").lower()
        if domain:
            domains.append(domain)
        if any(h in domain for h in TELEMETRY_DOMAIN_HINTS):
            risky += 1
    unique = len(set(domains))
    score = min(CAP_EXTERNAL_DOMAIN, risky * 5 + min(unique, 5) * 2)
    return (
        score,
        f"Router DNS queries observed: {unique} unique domains ({risky} telemetry-pattern matches)",
    )


def _recurrence(observations: list[dict[str, Any]]) -> tuple[float, str]:
    by_hour: Counter[str] = Counter()
    for o in observations:
        hour = (o.get("timestamp_utc") or "")[:13]
        src = o.get("source_ip") or "unknown"
        if hour:
            by_hour[f"{src}:{hour}"] += 1
    sessions = sum(1 for c in by_hour.values() if c >= 2)
    score = min(CAP_RECURRENCE, sessions * 4)
    return score, f"Recurrent discovery sessions: {sessions}"


def _evidence_discount(
    sources: set[str],
    classification: str,
    event_count: int,
) -> tuple[float, str]:
    discount = 0.0
    reasons: list[str] = []
    if EvidenceSource.ROUTER_LEVEL_EVIDENCE.value not in sources:
        discount += 10
        reasons.append("host-only evidence")
    if classification == LanClassification.INSUFFICIENT_EVIDENCE.value:
        discount += 15
        reasons.append("insufficient evidence classification")
    if event_count < 3:
        discount += 10
        reasons.append("low event volume")
    discount = min(CAP_DISCOUNT, discount)
    return discount, "; ".join(reasons) or "minimal discount"


def compute_privacy_risk_score(
    *,
    observations: list[dict[str, Any]],
    devices: list[dict[str, Any]] | None = None,
    router_events: list[dict[str, Any]] | None = None,
    classification: str = "",
) -> PrivacyRiskScoreResult:
    """Compute a transparent, capped Privacy Risk Score with component breakdown.

    Aggregates six independent scoring components and applies an evidence-confidence
    discount before capping the result in [0.0, 100.0].  The score is an ordinal
    governance input — not a malware detection probability.

    Components:
        * ``discovery_breadth``: Unique targets and sources (cap 20).
        * ``probe_frequency``: Total probe/discovery event count (cap 20).
        * ``unknown_vendor_weight``: Ratio of unknown-OUI devices (cap 15).
        * ``external_domain_risk``: Router DNS telemetry-pattern matches (cap 25).
        * ``recurrence``: Sessions with repeated probing from the same source (cap 20).
        * ``evidence_confidence_discount``: Discount for host-only or low-volume evidence (cap 30).

    Args:
        observations: Flat list of ``LanObservation``-compatible dicts.
        devices: Optional device inventory list for vendor-weight computation.
        router_events: Optional router DNS/DHCP event list for external-domain risk.
        classification: Primary ``LanClassification`` string used for discount and
            human-review flag computation.

    Returns:
        A ``PrivacyRiskScoreResult`` with score, level, tier, per-component
        breakdown, explanation, limitations, and human-review recommendation.
    """
    devices = devices or []
    router_events = router_events or []
    sources = {
        o.get("evidence_source", EvidenceSource.HOST_LEVEL_OBSERVATION.value) for o in observations
    }
    for e in router_events:
        sources.add(e.get("evidence_source", EvidenceSource.ROUTER_LEVEL_EVIDENCE.value))

    b_score, b_rationale = _discovery_breadth(observations + router_events)
    f_score, f_rationale = _probe_frequency(observations)
    u_score, u_rationale = _unknown_vendor_weight(devices)
    e_score, e_rationale = _external_domain_risk(router_events)
    r_score, r_rationale = _recurrence(observations)
    d_score, d_rationale = _evidence_discount(sources, classification, len(observations))

    raw = b_score + f_score + u_score + e_score + r_score - d_score
    numeric = max(0.0, min(100.0, raw))
    level = _risk_level(numeric)
    tier = _evidence_tier(sources, len(observations))

    limitations = list(LAN_LIMITATIONS)
    if EvidenceSource.ROUTER_LEVEL_EVIDENCE.value not in sources:
        limitations.append("External domain risk requires router DNS log import.")

    explanation = (
        f"Privacy risk score {numeric:.0f} ({level}) based on observed local network activity. "
        f"Discovery breadth and probe frequency contribute positively; evidence confidence discount "
        f"applied ({d_rationale}). This is ordinal governance input — not proof of spying or data theft."
    )

    human_review = level == "HIGH" or classification in {
        LanClassification.POSSIBLE_LATERAL_RECON.value,
        LanClassification.BROAD_SUBNET_PROBING.value,
    }

    return PrivacyRiskScoreResult(
        numeric_score=round(numeric, 1),
        risk_level=level,
        evidence_tier=tier,
        components={
            "discovery_breadth": {"score": round(b_score, 1), "rationale": b_rationale},
            "probe_frequency": {"score": round(f_score, 1), "rationale": f_rationale},
            "unknown_vendor_weight": {"score": round(u_score, 1), "rationale": u_rationale},
            "external_domain_risk": {"score": round(e_score, 1), "rationale": e_rationale},
            "recurrence": {"score": round(r_score, 1), "rationale": r_rationale},
            "evidence_confidence_discount": {"score": round(d_score, 1), "rationale": d_rationale},
        },
        explanation=explanation,
        limitations=limitations,
        evidence_sources_present=sorted(sources),
        human_review_recommended=human_review,
    )

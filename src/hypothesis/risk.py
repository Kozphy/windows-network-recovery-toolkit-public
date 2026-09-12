"""Ordinal impact weights for hypotheses; risk_score = clamp(confidence * impact).

Not calibrated probability — a minimal lever for prioritization under uncertainty.
"""

from __future__ import annotations

from typing import Final

from .keys import ALL_HYPOTHESES, HypothesisKey

# 0–1 remediation / harm proxy (minimal static table).
_IMPACT: Final[dict[HypothesisKey, float]] = {
    "local_proxy_hijack": 0.92,
    "localhost_proxy_owner_suspicious": 0.88,
    "unexpected_user_proxy": 0.75,
    "browser_proxy_path_issue": 0.70,
    "winhttp_proxy_issue": 0.72,
    "tls_path_issue": 0.78,
    "dns_resolution_issue": 0.65,
    "winsock_corruption_possible": 0.85,
    "socket_exhaustion": 0.72,
    "isp_router_path_issue": 0.55,
}


def hypothesis_impact(key: HypothesisKey) -> float:
    """Static impact ordinal in ``[0, 1]`` for ``key`` (unknown keys get a middling default)."""
    return float(_IMPACT.get(key, 0.52))


def hypothesis_risk_score(confidence: float, key: HypothesisKey) -> float:
    """Combine probability-like confidence with static impact ordinal (product, clamped, rounded)."""
    p = max(0.0, min(1.0, float(confidence)))
    hit = hypothesis_impact(key)
    return round(max(0.0, min(1.0, p * hit)), 4)


def default_impacts_table() -> dict[str, float]:
    """All keys for audit consumers."""
    return {k: hypothesis_impact(k) for k in ALL_HYPOTHESES}

"""Human-readable summaries for ranked live hypotheses."""

from __future__ import annotations

from ..core.models import LiveNetworkSnapshot
from .live_scoring import LiveHypothesisScore


def primary_explanation_paragraph(snap: LiveNetworkSnapshot, top: LiveHypothesisScore) -> str:
    """Produce a concise narrative anchored to ranked hypothesis plus live probes.

    Args:
        snap: Frozen observability snapshot (registry + FeatureVector correlations).
        top: Highest-confidence ``LiveHypothesisScore`` emitted by deterministic ranking.

    Returns:
        Plaintext paragraph suitable for operator logs (no Markdown).

    Constraints:
        Intentionally English-only; avoids claiming malware verdicts beyond supplied evidence tiers.
    """
    reg = snap.proxy_registry
    parsed = snap.parsed_proxy
    fv = snap.feature_vector
    proxy_on = reg.proxy_enable == 1

    bits = []
    bits.append(f"Primary hypothesis `{top.hypothesis}` scored {top.confidence:.2f}.")
    if proxy_on and parsed.is_localhost_proxy:
        port = parsed.localhost_port or "?"
        bits.append(
            "Chrome/Edge failures are consistent with browser traffic routed through an unexpected "
            f"localhost proxy (ProxyServer references loopback:{port}).",
        )
        if fv.browser_http_ok and fv.tcp_443_ok:
            bits.append(
                "Automated curl HTTPS and TCP 443 probes succeeded, which makes a full Internet outage unlikely.",
            )
    elif top.hypothesis == "dns_resolution_issue":
        bits.append("Symptoms align with DNS resolution impairment while IP reachability may still succeed.")
    else:
        bits.append("Review evidence bullets and negative evidence alongside raw snapshot JSON.")

    return " ".join(bits)

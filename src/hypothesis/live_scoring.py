"""Deterministic live hypothesis scoring over ``LiveNetworkSnapshot`` inputs.

Decision intent:
    Quantify plausible Windows connectivity failure modes without ML, preserving evidence bullets
    and explicit negative-evidence statements for pairwise review.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..attribution.suspicious_process import diagnostic_suspicion_tier
from ..core.models import LiveNetworkSnapshot
from .keys import ALL_HYPOTHESES, HypothesisKey

_CONNECTION_TW_SPIKE = 5000
_CONNECTION_EST_SPIKE = 8000


def _clamp(x: float) -> float:
    return max(0.0, min(1.0, x))


@dataclass(frozen=True)
class LiveHypothesisScore:
    """Deterministic hypothesis confidence with supporting and negative evidence."""

    hypothesis: HypothesisKey
    confidence: float
    evidence: tuple[str, ...]
    negative_evidence: tuple[str, ...]


def _empty_scores() -> dict[HypothesisKey, tuple[float, list[str], list[str]]]:
    return {h: (0.06, [], []) for h in ALL_HYPOTHESES}


def _bump(
    bag: dict[HypothesisKey, tuple[float, list[str], list[str]]],
    key: HypothesisKey,
    amt: float,
    note: str,
) -> None:
    conf, ev, neg = bag[key]
    bag[key] = (conf + amt, ev + [note], neg)


def _add_neg(
    bag: dict[HypothesisKey, tuple[float, list[str], list[str]]],
    key: HypothesisKey,
    note: str,
) -> None:
    conf, ev, neg = bag[key]
    bag[key] = (conf, ev, neg + [note])


def score_live_snapshot(snap: LiveNetworkSnapshot) -> tuple[LiveHypothesisScore, ...]:
    """Rank v2 hypotheses from a live observability snapshot (deterministic, rule-based)."""
    fv = snap.feature_vector
    reg = snap.proxy_registry
    parsed = snap.parsed_proxy
    bag = _empty_scores()

    user_proxy_on = reg.proxy_enable == 1
    stacked = (
        int(not fv.ping_ip_ok)
        + int(not fv.nslookup_ok)
        + int(not fv.tcp_443_ok)
        + int(not fv.browser_http_ok)
    )

    # Negative evidence shared
    if fv.nslookup_ok:
        n = "DNS lookup succeeded, so this is less likely to be a DNS-only issue."
        _add_neg(bag, "dns_resolution_issue", n)
    if fv.tcp_443_ok:
        _add_neg(bag, "unexpected_user_proxy", "TCP 443 succeeded, so remote TLS reachability is available.")
        _add_neg(bag, "tls_path_issue", "TCP 443 succeeded; failures are more likely app-layer or proxy path.")
    if fv.browser_http_ok:
        _add_neg(bag, "browser_proxy_path_issue", "Automated curl HTTPS succeeded.")
        _add_neg(bag, "tls_path_issue", "curl HTTPS succeeded.")

    # unexpected_user_proxy (localhost manual proxy + healthy transport)
    if user_proxy_on and parsed.is_localhost_proxy and fv.tcp_443_ok and fv.nslookup_ok and fv.browser_http_ok:
        _bump(
            bag,
            "unexpected_user_proxy",
            0.86,
            "Windows user proxy is enabled and points to a loopback address while curl HTTPS and TCP 443 succeed.",
        )
    elif user_proxy_on and parsed.is_localhost_proxy and fv.tcp_443_ok and fv.nslookup_ok:
        _bump(
            bag,
            "unexpected_user_proxy",
            0.78,
            "User-level proxy targets loopback; transport probes succeed—browser-only failures are plausible.",
        )

    if snap.port_owners:
        _bump(
            bag,
            "unexpected_user_proxy",
            0.04,
            f"Local listener attribution found {len(snap.port_owners)} process(es) for the proxy port.",
        )

    # localhost_proxy_owner_suspicious
    for o in snap.port_owners:
        tier = diagnostic_suspicion_tier(
            o.process_name,
            localhost_proxy_owner=True,
            command_line_unavailable=o.command_line is None,
        )
        if tier == "high" and user_proxy_on and parsed.is_localhost_proxy:
            _bump(
                bag,
                "localhost_proxy_owner_suspicious",
                0.55,
                f"Local proxy owner '{o.process_name or 'unknown'}' has limited visibility (command line missing).",
            )
        elif tier == "medium" and user_proxy_on and parsed.is_localhost_proxy:
            _bump(
                bag,
                "localhost_proxy_owner_suspicious",
                0.35,
                f"Local proxy owner '{o.process_name or 'unknown'}' matches tooling often used for intercepts.",
            )

    # local_proxy_hijack (stronger wording when owner + localhost proxy)
    if user_proxy_on and parsed.is_localhost_proxy and snap.port_owners:
        _bump(
            bag,
            "local_proxy_hijack",
            0.62,
            "Loopback proxy is active and a listening process was attributed to the proxy port.",
        )

    # browser_proxy_path_issue
    if fv.proxy_enabled and not fv.browser_http_ok and fv.tcp_443_ok and fv.nslookup_ok:
        _bump(
            bag,
            "browser_proxy_path_issue",
            0.58,
            "Proxy signals are on, curl HTTPS failed, but TCP 443 still succeeds—check WinINET/WinHTTP split and browser policy.",
        )
    if user_proxy_on and not fv.browser_http_ok and fv.tcp_443_ok:
        _bump(
            bag,
            "browser_proxy_path_issue",
            0.45,
            "User proxy flag is set while automated HTTPS probe failed despite working TCP 443.",
        )

    # socket_exhaustion
    if fv.time_wait_count >= _CONNECTION_TW_SPIKE or fv.established_count >= _CONNECTION_EST_SPIKE:
        ratio = max(
            fv.time_wait_count / max(_CONNECTION_TW_SPIKE, 1),
            fv.established_count / max(_CONNECTION_EST_SPIKE, 1),
        )
        _bump(
            bag,
            "socket_exhaustion",
            _clamp(0.32 + 0.25 * ratio),
            "TIME_WAIT/ESTABLISHED counters are elevated—possible socket churn or leaks.",
        )

    # dns_resolution_issue
    if fv.ping_ip_ok and not fv.nslookup_ok:
        _bump(
            bag,
            "dns_resolution_issue",
            0.72,
            "ICMP to a public IP succeeded while DNS resolution failed.",
        )

    # tls_path_issue
    if fv.tls_cert_issue_detected:
        _bump(
            bag,
            "tls_path_issue",
            0.48,
            "TLS/certificate keywords appeared in curl output—inspect inspection proxies or trust store issues.",
        )
    if fv.tcp_443_ok and not fv.browser_http_ok and not fv.proxy_enabled:
        _bump(
            bag,
            "tls_path_issue",
            0.36,
            "TCP 443 succeeded but curl HTTPS failed without user proxy signals—TLS or filtering path is suspect.",
        )

    # winhttp_proxy_issue
    if fv.winhttp_proxy_enabled and not fv.browser_http_ok:
        _bump(
            bag,
            "winhttp_proxy_issue",
            0.44,
            "WinHTTP reports a non-direct proxy and HTTPS probing failed.",
        )

    # winsock_corruption_possible
    if stacked >= 3:
        _bump(
            bag,
            "winsock_corruption_possible",
            0.55,
            "Multiple independent transport checks failed—stack corruption is possible after link health is verified.",
        )
    elif not fv.tcp_443_ok and fv.ping_ip_ok and fv.nslookup_ok:
        _bump(
            bag,
            "winsock_corruption_possible",
            0.34,
            "TCP 443 failed while ICMP/DNS succeeded—Winsock or path filtering is plausible.",
        )

    # isp_router_path_issue
    if fv.gateway_reachable is False:
        _bump(
            bag,
            "isp_router_path_issue",
            0.55,
            "Default gateway ping failed—local segment or router path is suspect.",
        )
    elif fv.gateway_reachable is True and not fv.ping_ip_ok:
        _bump(
            bag,
            "isp_router_path_issue",
            0.48,
            "Gateway responds but WAN ICMP failed—ISP/upstream outage is plausible.",
        )

    out: list[LiveHypothesisScore] = []
    for key in ALL_HYPOTHESES:
        conf, ev, neg = bag[key]
        notes = tuple(ev) if ev else ("Baseline prior only.",)
        negt = tuple(neg)
        out.append(
            LiveHypothesisScore(
                hypothesis=key,
                confidence=_clamp(conf),
                evidence=notes,
                negative_evidence=negt,
            ),
        )

    out.sort(key=lambda s: (-s.confidence, s.hypothesis))
    return tuple(out)


def ranked_dicts(scores: tuple[LiveHypothesisScore, ...]) -> list[dict[str, object]]:
    """Serialize ranked hypotheses for JSON audit exports."""
    rows: list[dict[str, object]] = []
    for idx, s in enumerate(scores, start=1):
        rows.append(
            {
                "rank": idx,
                "hypothesis": s.hypothesis,
                "confidence": s.confidence,
                "evidence": list(s.evidence),
                "negative_evidence": list(s.negative_evidence),
            },
        )
    return rows

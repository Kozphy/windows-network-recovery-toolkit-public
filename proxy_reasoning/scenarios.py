"""Canonical proxy failure scenarios and pattern matchers.

Module responsibility:
    Rank ``ProxyHypothesis`` rows for the four CASE_* scenarios using signal patterns.

Decision intent:
    Prefer the highest-scoring scenario with explicit rejection reasons for alternates.

Engineering Notes:
    Scenario matchers are intentionally conservative — ambiguous inputs yield lower confidence.
"""

from __future__ import annotations

from typing import Any

from proxy_reasoning.constants import (
    ATTRIBUTION_LIMITATION,
    CASE_BROWSER_PROXY_PATH_ISSUE,
    CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION,
    CASE_LOCALHOST_PROXY_LISTENER,
    CASE_WININET_PROXY_DRIFT,
)
from proxy_reasoning.models import ProxyHypothesis, ProxySignal


def _signal_map(signals: list[ProxySignal]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for sig in signals:
        out[sig.name] = sig.value
    return out


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "ok", "success", "enabled", "on"}
    return bool(value)


def _has(signals: dict[str, Any], name: str) -> bool:
    return _truthy(signals.get(name))


def match_wininet_proxy_drift(signals: dict[str, Any]) -> ProxyHypothesis | None:
    """CASE_WININET_PROXY_DRIFT: WinINET enabled with unexpected/localhost server; WinHTTP may be direct."""
    if not _has(signals, "wininet_proxy_enabled"):
        return None
    if not (_has(signals, "wininet_winhttp_divergent") or _has(signals, "proxy_server_localhost")):
        return None
    supporting = [
        n
        for n in ("wininet_proxy_enabled", "wininet_winhttp_divergent", "proxy_server_localhost")
        if _has(signals, n)
    ]
    return ProxyHypothesis(
        case_id=CASE_WININET_PROXY_DRIFT,
        title="WinINET proxy drift vs WinHTTP or prior state",
        confidence_rank="high" if len(supporting) >= 2 else "medium",
        evidence_level="inferred",
        supporting_signals=supporting,
        limitations=[
            "Registry observation does not prove which component enabled the proxy.",
            ATTRIBUTION_LIMITATION,
        ],
    )


def match_localhost_proxy_listener(signals: dict[str, Any]) -> ProxyHypothesis | None:
    """CASE_LOCALHOST_PROXY_LISTENER: loopback proxy with optional listener attribution."""
    if not (_has(signals, "proxy_server_localhost") or _has(signals, "is_loopback_proxy")):
        return None
    supporting = [
        n
        for n in ("proxy_server_localhost", "is_loopback_proxy", "listener_on_proxy_port")
        if _has(signals, n)
    ]
    limitations = [ATTRIBUTION_LIMITATION]
    if _has(signals, "listener_process_name"):
        limitations.append(
            f"Listener process name observed ({signals.get('listener_process_name')!r}) is heuristic only.",
        )
    return ProxyHypothesis(
        case_id=CASE_LOCALHOST_PROXY_LISTENER,
        title="Localhost proxy path with listener correlation",
        confidence_rank="high" if _has(signals, "listener_on_proxy_port") else "medium",
        evidence_level="inferred",
        supporting_signals=supporting,
        limitations=limitations,
    )


def match_browser_proxy_path_issue(signals: dict[str, Any]) -> ProxyHypothesis | None:
    """CASE_BROWSER_PROXY_PATH_ISSUE: DNS/ping ok, browser path fails, bypass may succeed."""
    core = _has(signals, "dns_ok") and _has(signals, "ping_ok")
    browser_fail = _has(signals, "browser_https_failed") or _has(signals, "browser_works") is False
    if not core or not browser_fail:
        return None
    supporting = [
        n
        for n in ("ping_ok", "dns_ok", "browser_https_failed", "curl_https_ok")
        if _has(signals, n)
    ]
    if _has(signals, "proxy_bypass_succeeded"):
        supporting.append("proxy_bypass_succeeded")
    rank: str = "high" if _has(signals, "proxy_bypass_succeeded") else "medium"
    return ProxyHypothesis(
        case_id=CASE_BROWSER_PROXY_PATH_ISSUE,
        title="Browser/proxy path issue with transport layer appearing healthy",
        confidence_rank=rank,  # type: ignore[arg-type]
        evidence_level="inferred",
        supporting_signals=supporting,
        limitations=[
            "Ping and DNS success do not prove browser-path success.",
            ATTRIBUTION_LIMITATION,
        ],
    )


def match_electron_app_firewall(signals: dict[str, Any]) -> ProxyHypothesis | None:
    """CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION: browser ok, electron app fails."""
    if not (_has(signals, "browser_works") or _has(signals, "browser_https_ok")):
        return None
    if not (_has(signals, "electron_app_failed") or _has(signals, "app_fails")):
        return None
    limitations = [
        "Electron/desktop app failure with healthy browser path does not prove firewall root cause.",
        ATTRIBUTION_LIMITATION,
    ]
    if _has(signals, "firewall_reset_helped"):
        limitations.append(
            "Firewall reset helped is observational feedback only; before/after proof is required for causality.",
        )
    rank: str = "medium"
    if _has(signals, "firewall_reset_helped") and _has(signals, "electron_app_failed_before"):
        rank = "high"
    return ProxyHypothesis(
        case_id=CASE_ELECTRON_APP_PROXY_FIREWALL_INTERACTION,
        title="Electron/desktop app path degraded while browser path healthy",
        confidence_rank=rank,  # type: ignore[arg-type]
        evidence_level="inferred",
        supporting_signals=[
            n
            for n in (
                "browser_works",
                "browser_https_ok",
                "electron_app_failed",
                "app_fails",
                "curl_https_ok",
                "firewall_reset_helped",
            )
            if _has(signals, n)
        ],
        limitations=limitations,
    )


def rank_hypotheses(signals: list[ProxySignal]) -> list[ProxyHypothesis]:
    """Evaluate all canonical scenarios and return ranked hypotheses (highest confidence first)."""
    smap = _signal_map(signals)
    candidates: list[ProxyHypothesis] = []
    for matcher in (
        match_browser_proxy_path_issue,
        match_wininet_proxy_drift,
        match_localhost_proxy_listener,
        match_electron_app_firewall,
    ):
        hyp = matcher(smap)
        if hyp is not None:
            candidates.append(hyp)
    order = {"high": 0, "medium": 1, "low": 2}
    candidates.sort(key=lambda h: order.get(h.confidence_rank, 3))
    return candidates

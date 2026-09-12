"""Proxy path operational assessment (registry posture vs reachable browser path).

Separates WinINET registry signals from whether traffic can traverse the configured
localhost proxy chain. Same ``ProxyEnable=1`` may be healthy or broken depending on
listener and HTTPS contrast (proxied vs bypass), not registry alone.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from ..proof.proxy_https import _curl_https_probe, _curl_proxy_url, _interpret_curl_https_ok
from .parser import ParsedProxy

ProxyPathComposite = Literal[
    "DIRECT",
    "LATENT_MISCONFIG",
    "LOOPBACK_OPERATIONAL",
    "LOOPBACK_BROKEN",
    "ENTERPRISE_PAC",
]

PolicyRecommendation = Literal["observe_no_rollback", "remediation_preview", "insufficient_signal"]

EvidenceTier = Literal[
    "TIER_0_RAW_OBSERVATION",
    "TIER_1_CORRELATED_SIGNAL",
    "TIER_2_CONTRAST_TESTED",
]

_DEFAULT_TEST_URL = "https://www.google.com"


@dataclass(frozen=True)
class ProxyPathOperationalAssessment:
    """Registry + operational posture for one capture instant."""

    composite_state: ProxyPathComposite
    registry_posture: dict[str, Any]
    operational: dict[str, Any]
    evidence_tier: EvidenceTier
    policy_recommendation: PolicyRecommendation
    epistemic_chain: dict[str, str]
    human_summary: str

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "composite_state": self.composite_state,
            "registry_posture": dict(self.registry_posture),
            "operational": dict(self.operational),
            "evidence_tier": self.evidence_tier,
            "policy_recommendation": self.policy_recommendation,
            "epistemic_chain": dict(self.epistemic_chain),
            "human_summary": self.human_summary,
        }


def _norm_url(val: str | None) -> str:
    return (val or "").strip()


def _tri_bool_label(val: bool | None) -> str:
    if val is True:
        return "true"
    if val is False:
        return "false"
    return "unknown"


def _run_bypass_https(
    *,
    test_url: str,
    run: Callable[..., Any],
    curl_timeout: float,
) -> bool:
    code_b, out_b, _ = _curl_https_probe(
        test_url,
        proxy_url=None,
        noproxy_all=True,
        subprocess_run=run,
        timeout=curl_timeout,
    )
    return _interpret_curl_https_ok(code_b, out_b)


def _run_https_contrast(
    *,
    parsed: ParsedProxy,
    proxy_enable: int | None,
    test_url: str,
    run: Callable[..., Any],
    curl_timeout: float,
) -> tuple[bool | None, bool | None]:
    """Return (proxied_https_ok, bypass_https_ok); proxied is ``None`` when not applicable."""
    bypass_ok = _run_bypass_https(test_url=test_url, run=run, curl_timeout=curl_timeout)
    if proxy_enable != 1 or not parsed.is_localhost_proxy:
        return None, bypass_ok
    proxy_url, _scheme = _curl_proxy_url(parsed)
    if not proxy_url:
        return None, bypass_ok
    code_p, out_p, _ = _curl_https_probe(
        test_url,
        proxy_url=proxy_url,
        noproxy_all=False,
        subprocess_run=run,
        timeout=curl_timeout,
    )
    return _interpret_curl_https_ok(code_p, out_p), bypass_ok


def classify_composite_state(
    *,
    proxy_enable: int | None,
    proxy_server: str | None,
    auto_config_url: str | None,
    parsed: ParsedProxy,
    listener_up: bool | None,
    proxied_https_ok: bool | None,
    bypass_https_ok: bool | None,
) -> ProxyPathComposite:
    """Map observations to composite state (inference layer; not proof of writer)."""
    pac = _norm_url(auto_config_url)
    if pac:
        return "ENTERPRISE_PAC"

    enabled = proxy_enable == 1
    server_set = bool(_norm_url(proxy_server))

    if not enabled and not server_set:
        return "DIRECT"

    if not enabled and server_set and parsed.is_localhost_proxy:
        return "LATENT_MISCONFIG"

    if not enabled and server_set:
        return "LATENT_MISCONFIG"

    if enabled and parsed.is_localhost_proxy:
        if proxied_https_ok is False and bypass_https_ok is True:
            return "LOOPBACK_BROKEN"
        if listener_up is False:
            return "LOOPBACK_BROKEN"
        if proxied_https_ok is True:
            return "LOOPBACK_OPERATIONAL"
        if listener_up is True and proxied_https_ok is None:
            return "LOOPBACK_OPERATIONAL"
        if proxied_https_ok is False:
            return "LOOPBACK_BROKEN"
        return "LOOPBACK_BROKEN"

    return "DIRECT"


def policy_for_composite(state: ProxyPathComposite) -> PolicyRecommendation:
    """Operator policy hint from composite state (orthogonal to registry-writer proof)."""
    if state == "LOOPBACK_BROKEN":
        return "remediation_preview"
    if state in {"LOOPBACK_OPERATIONAL", "ENTERPRISE_PAC", "DIRECT", "LATENT_MISCONFIG"}:
        return "observe_no_rollback"
    return "insufficient_signal"


def evidence_tier_for(
    *,
    composite: ProxyPathComposite,
    proxied_https_ok: bool | None,
    bypass_https_ok: bool | None,
    listener_up: bool | None,
) -> EvidenceTier:
    """Evidence tier for.
    
    Args:
        composite: The composite value supplied by the caller.
        proxied_https_ok: The proxied https ok value supplied by the caller.
        bypass_https_ok: The bypass https ok value supplied by the caller.
        listener_up: The listener up value supplied by the caller.
    
    Returns:
        The EvidenceTier result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if proxied_https_ok is not None and bypass_https_ok is not None:
        return "TIER_2_CONTRAST_TESTED"
    if listener_up is not None or composite in {"LOOPBACK_OPERATIONAL", "LOOPBACK_BROKEN"}:
        return "TIER_1_CORRELATED_SIGNAL"
    return "TIER_0_RAW_OBSERVATION"


def browser_path_healthy(
    *,
    composite: ProxyPathComposite,
    proxied_https_ok: bool | None,
    bypass_https_ok: bool | None,
) -> bool | None:
    """Browser path healthy.
    
    Args:
        composite: The composite value supplied by the caller.
        proxied_https_ok: The proxied https ok value supplied by the caller.
        bypass_https_ok: The bypass https ok value supplied by the caller.
    
    Returns:
        The bool | None result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if composite == "LOOPBACK_OPERATIONAL":
        return True if proxied_https_ok is not False else proxied_https_ok
    if composite == "LOOPBACK_BROKEN":
        return False
    if composite == "DIRECT":
        return True if bypass_https_ok is True else (True if bypass_https_ok is None else bypass_https_ok)
    if composite == "LATENT_MISCONFIG":
        return True if bypass_https_ok is not False else bypass_https_ok
    return None


def human_summary_for(
    *,
    composite: ProxyPathComposite,
    registry_posture: dict[str, Any],
    operational: dict[str, Any],
) -> str:
    """Human summary for.
    
    Args:
        composite: The composite value supplied by the caller.
        registry_posture: The registry posture value supplied by the caller.
        operational: The operational value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    pe = registry_posture.get("proxy_enable")
    if composite == "DIRECT":
        return "WinINET proxy off (or non-loopback); browser path not forced through localhost proxy."
    if composite == "LATENT_MISCONFIG":
        return (
            "ProxyServer points at loopback but ProxyEnable is off — latent misconfig; "
            "browser may still work until proxy is enabled."
        )
    if composite == "ENTERPRISE_PAC":
        return "PAC/AutoConfigURL drives routing; loopback ProxyServer alone does not describe the path."
    if composite == "LOOPBACK_OPERATIONAL":
        return (
            f"Loopback proxy enabled (ProxyEnable={pe}) with operational path "
            f"(listener={operational.get('listener_up')}, proxied_https={operational.get('proxied_https_ok')})."
        )
    return (
        f"Loopback proxy enabled (ProxyEnable={pe}) but path non-operational "
        f"(listener={operational.get('listener_up')}, proxied_https={operational.get('proxied_https_ok')}, "
        f"bypass_https={operational.get('bypass_https_ok')})."
    )


def assess_proxy_path_operational(
    *,
    proxy_enable: int | None,
    proxy_server: str | None,
    auto_config_url: str | None,
    parsed: ParsedProxy,
    port_listen: bool | None,
    run: Callable[..., Any] = subprocess.run,
    include_https_contrast: bool = True,
    test_url: str = _DEFAULT_TEST_URL,
    timeout_seconds: float = 12.0,
) -> ProxyPathOperationalAssessment:
    """Assess registry posture and optional operational probes for the proxy path.

    Args:
        proxy_enable: HKCU ProxyEnable (0/1/None).
        proxy_server: HKCU ProxyServer string.
        auto_config_url: HKCU AutoConfigURL.
        parsed: Parsed ProxyServer structure.
        port_listen: Tri-state localhost listener probe for the attributed port.
        run: Injectable subprocess runner (tests).
        include_https_contrast: When True, run curl proxied vs ``--noproxy`` contrast.
        test_url: HTTPS URL for contrast probes.
        timeout_seconds: Per-probe curl budget.

    Returns:
        Frozen assessment with composite state, evidence tier, and policy recommendation.
    """
    registry_posture = {
        "proxy_enable": proxy_enable,
        "proxy_server": proxy_server,
        "auto_config_url": auto_config_url or None,
        "is_localhost_proxy": parsed.is_localhost_proxy,
        "localhost_port": parsed.localhost_port,
        "proxy_mode": parsed.proxy_mode,
    }

    proxied_https_ok: bool | None = None
    bypass_https_ok: bool | None = None
    if include_https_contrast:
        proxied_https_ok, bypass_https_ok = _run_https_contrast(
            parsed=parsed,
            proxy_enable=proxy_enable,
            test_url=test_url,
            run=run,
            curl_timeout=timeout_seconds,
        )
    else:
        bypass_https_ok = _run_bypass_https(test_url=test_url, run=run, curl_timeout=timeout_seconds)

    listener_up = port_listen
    composite = classify_composite_state(
        proxy_enable=proxy_enable,
        proxy_server=proxy_server,
        auto_config_url=auto_config_url,
        parsed=parsed,
        listener_up=listener_up,
        proxied_https_ok=proxied_https_ok,
        bypass_https_ok=bypass_https_ok,
    )
    tier = evidence_tier_for(
        composite=composite,
        proxied_https_ok=proxied_https_ok,
        bypass_https_ok=bypass_https_ok,
        listener_up=listener_up,
    )
    policy = policy_for_composite(composite)
    operational = {
        "listener_up": listener_up,
        "proxied_https_ok": proxied_https_ok,
        "bypass_https_ok": bypass_https_ok,
        "browser_path_healthy": browser_path_healthy(
            composite=composite,
            proxied_https_ok=proxied_https_ok,
            bypass_https_ok=bypass_https_ok,
        ),
    }
    summary = human_summary_for(
        composite=composite,
        registry_posture=registry_posture,
        operational=operational,
    )
    epistemic = {
        "observation": (
            f"ProxyEnable={proxy_enable}; ProxyServer={proxy_server or '(empty)'}; "
            f"listener_up={_tri_bool_label(listener_up)}"
        ),
        "event": "proxy_path_assessed",
        "state": composite,
        "hypothesis": (
            "Browser path failure requires non-operational loopback proxy path, not ProxyEnable alone."
            if composite == "LOOPBACK_BROKEN"
            else "Registry posture recorded; path operational where composite state indicates."
        ),
        "evidence_tier": tier,
        "policy": policy,
    }
    return ProxyPathOperationalAssessment(
        composite_state=composite,
        registry_posture=registry_posture,
        operational=operational,
        evidence_tier=tier,
        policy_recommendation=policy,
        epistemic_chain=epistemic,
        human_summary=summary,
    )

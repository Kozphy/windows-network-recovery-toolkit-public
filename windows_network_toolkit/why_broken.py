"""Unified read-only investigate: why browser/connectivity looks broken.

Module responsibility:
    Correlate proxy, DNS/Edge, and IPv6 path evidence into one ranked
    hypothesis list and a single ``operator_next_step``. Answers "why is it
    broken?" for Edge hangs / name errors without claiming attack attribution.

System placement:
    CLI: ``why-broken`` (read-only). Composes ``run_proxy_status``,
    ``diagnose_dns_edge``, and ``investigate_ipv6_path`` (or injects).

Key invariants:
    * Read-only; dry-run remediations are only recommended, never applied here.
    * Observation ≠ proof; classification ≠ accusation.
    * Coding apps working while Edge hangs is an expected dual-stack pattern.

Side effects:
    Outbound probes and registry/DNS reads via child modules; no remediation.

Failure modes:
    Non-Windows without inject → unsupported. Partial probe failure →
    degraded confidence and limitations.

Audit Notes:
    What could go wrong: wrong primary hypothesis if one probe flake.
    Detection: compare ``hypotheses[]`` scores and re-run with ``--url``.
    Recovery: follow ``operator_next_step.command``; do not treat as MITM proof.
"""

from __future__ import annotations

import platform
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from windows_network_toolkit.safety import DEFAULT_SAFETY_NOTES

HypothesisFn = Callable[..., dict[str, Any]]


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _unsupported() -> dict[str, Any]:
    return {
        "unsupported_platform": True,
        "platform": platform.system(),
        "message": "why-broken requires Windows (or inject fixtures).",
        "limitations": list(DEFAULT_SAFETY_NOTES),
    }


def probe_url_families(
    url: str,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    """Probe a URL with curl IPv4-only and IPv6-only (read-only).

    Args:
        url: Absolute http(s) URL.
        run: Optional subprocess runner (tests).
        timeout: Per-probe seconds.

    Returns:
        Dict with ``ipv4`` / ``ipv6`` probe rows and normalized host.
    """
    run_fn = run or subprocess.run
    host = urlparse(url).hostname or url

    def _one(flag: str) -> dict[str, Any]:
        if platform.system() != "Windows" and run is None:
            return {"ok": False, "family": flag.lstrip("-"), "error": "requires_windows"}
        try:
            completed = run_fn(
                ["curl.exe", flag, "-I", "-sS", "--max-time", str(int(timeout)), url],
                capture_output=True,
                text=True,
                timeout=timeout + 5,
                check=False,
            )
            out = (completed.stdout or "") + (completed.stderr or "")
            ok = completed.returncode == 0 and (
                "HTTP/" in out or "HTTP/2" in out or "HTTP/3" in out
            )
            return {
                "ok": ok,
                "family": "ipv4" if flag == "-4" else "ipv6",
                "returncode": completed.returncode,
                "excerpt": out.strip()[:240] or None,
                "error": None if ok else f"curl_exit={completed.returncode}",
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {
                "ok": False,
                "family": "ipv4" if flag == "-4" else "ipv6",
                "error": str(exc)[:200],
            }

    return {"url": url, "host": host, "ipv4": _one("-4"), "ipv6": _one("-6")}


def _proxy_signal(proxy: dict[str, Any] | None) -> dict[str, Any]:
    if not proxy:
        return {
            "id": "proxy",
            "classification": "UNKNOWN",
            "score": 0.0,
            "summary": "Proxy status unavailable.",
        }
    cls = str(
        proxy.get("classification")
        or (proxy.get("classification_result") or {}).get("primary_classification")
        or "UNKNOWN"
    )
    score = 0.0
    if cls in {"DEAD_LOCALHOST_PROXY", "DEAD_PROXY", "LOCALHOST_PROXY_NO_LISTENER"}:
        score = 0.95
    elif cls in {"LOCALHOST_PROXY", "ACTIVE_LOCALHOST_PROXY", "SUSPICIOUS_PROXY"}:
        score = 0.85
    elif cls in {"PAC_CONFIGURED", "WINHTTP_PROXY"}:
        score = 0.55
    elif cls == "NO_PROXY":
        score = 0.05
    return {
        "id": "proxy",
        "classification": cls,
        "score": score,
        "summary": (proxy.get("classification_result") or {}).get("reasoning")
        or f"Proxy classification: {cls}",
        "next_command": (
            "python -m windows_network_toolkit proxy-disable --dry-run true"
            if score >= 0.8
            else "python -m windows_network_toolkit proxy-status"
        ),
    }


def _dns_signal(dns: dict[str, Any] | None) -> dict[str, Any]:
    if not dns:
        return {
            "id": "dns_edge",
            "classification": "UNKNOWN",
            "score": 0.0,
            "summary": "DNS/Edge status unavailable.",
        }
    cls = str(dns.get("classification") or "UNKNOWN")
    score = 0.0
    if cls == "DNS_RESOLVE_FAILED":
        score = 0.92
    elif cls == "ERR_NAME_NOT_RESOLVED_LIKELY":
        score = 0.8
    elif cls == "DNS_EDGE_OK":
        score = 0.05
    return {
        "id": "dns_edge",
        "classification": cls,
        "score": score,
        "summary": (dns.get("classification_result") or {}).get("reasoning")
        or f"DNS/Edge classification: {cls}",
        "next_command": (
            "python -m windows_network_toolkit dns-edge-fix --dry-run true"
            if score >= 0.7
            else "python -m windows_network_toolkit dns-edge-status"
        ),
    }


def _ipv6_signal(ipv6: dict[str, Any] | None) -> dict[str, Any]:
    if not ipv6:
        return {
            "id": "ipv6_path",
            "classification": "UNKNOWN",
            "score": 0.0,
            "summary": "IPv6 path status unavailable.",
        }
    path = ipv6.get("path") if isinstance(ipv6.get("path"), dict) else ipv6
    cls = str((path or {}).get("classification") or ipv6.get("classification") or "UNKNOWN")
    prefer = bool((path or {}).get("prefer_ipv4_bit_set") or ipv6.get("prefer_ipv4_bit_set"))
    ctx = ipv6.get("network_context") if isinstance(ipv6.get("network_context"), dict) else {}
    # With prefer-IPv4 set and no usable IPv6 source (no global address or Wi-Fi IPv6
    # unbound), clients have no IPv6 route to stall on — the blackhole is observed but inert.
    mitigated = (
        cls == "IPV6_PATH_BLACKHOLE"
        and prefer
        and (
            ctx.get("has_global_ipv6") is False
            or (path or {}).get("wifi_ipv6_binding_enabled") is False
        )
    )
    score = 0.0
    if mitigated:
        score = 0.2
    elif cls == "IPV6_PATH_BLACKHOLE":
        score = 0.88 if not prefer else 0.72
    elif cls == "NETWORK_PATH_DEGRADED":
        score = 0.7
    elif cls == "IPV6_PATH_OK":
        score = 0.05
    summary = ((path or {}).get("classification_result") or {}).get("reasoning") or (
        f"IPv6 path classification: {cls}"
    )
    if mitigated:
        summary += (
            " Mitigated: prefer-IPv4 is set and the host has no usable IPv6 "
            "(no global address or Wi-Fi IPv6 unbound), so the IPv6 blackhole is "
            "unlikely to stall Edge — check Edge client state with edge-triage."
        )
        next_cmd = "python -m windows_network_toolkit edge-triage"
    elif prefer and cls == "IPV6_PATH_BLACKHOLE":
        summary += (
            " Prefer-IPv4 bit is already set — Edge may still stall on third-party AAAA "
            "assets or show a blank/black UI (e.g. LinkedIn). Reboot if recently applied; "
            "else run browser-blank-screen or escalate Wi-Fi IPv6 binding."
        )
        next_cmd = "python -m windows_network_toolkit browser-blank-screen"
    elif score >= 0.7 and not prefer:
        next_cmd = "python -m windows_network_toolkit ipv6-prefer-ipv4 --dry-run true"
    else:
        next_cmd = "python -m windows_network_toolkit ipv6-path"
    return {
        "id": "ipv6_path",
        "classification": cls,
        "score": score,
        "prefer_ipv4_bit_set": prefer,
        "ipv6_mitigated": mitigated,
        "summary": summary,
        "next_command": next_cmd,
    }


def _url_signal(url_probe: dict[str, Any] | None) -> dict[str, Any] | None:
    if not url_probe:
        return None
    v4 = url_probe.get("ipv4") or {}
    v6 = url_probe.get("ipv6") or {}
    if v4.get("ok") and not v6.get("ok"):
        return {
            "id": "url_probe",
            "classification": "URL_IPV4_OK_IPV6_FAIL",
            "score": 0.65,
            "summary": (
                f"Target host {url_probe.get('host')} responds on IPv4 but not IPv6 — "
                "matches browser dual-stack hang pattern for pages with AAAA third parties."
            ),
            "next_command": "python -m windows_network_toolkit ipv6-path",
        }
    if not v4.get("ok") and not v6.get("ok"):
        return {
            "id": "url_probe",
            "classification": "URL_BOTH_FAIL",
            "score": 0.75,
            "summary": f"Target URL failed on both IPv4 and IPv6 probes: {url_probe.get('url')}",
            "next_command": "python -m windows_network_toolkit dns-edge-status",
        }
    if v4.get("ok"):
        return {
            "id": "url_probe",
            "classification": "URL_IPV4_OK",
            "score": 0.15,
            "summary": (
                "Target URL IPv4 OK — if Edge still spins or shows a blank/black page "
                "(LinkedIn pattern), run browser-blank-screen for GPU/cache cleanup."
            ),
            "next_command": "python -m windows_network_toolkit browser-blank-screen",
        }
    return None


def synthesize_why_broken(
    *,
    proxy: dict[str, Any] | None,
    dns: dict[str, Any] | None,
    ipv6: dict[str, Any] | None,
    url_probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rank hypotheses from proxy / DNS / IPv6 (/ optional URL) signals.

    Decision intent:
        Pick the highest-scoring brokenness hypothesis for operator next step
        without asserting malware or ISP malice.
    """
    signals = [_proxy_signal(proxy), _dns_signal(dns), _ipv6_signal(ipv6)]
    url_sig = _url_signal(url_probe)
    if url_sig:
        signals.append(url_sig)

    ranked = sorted(signals, key=lambda s: float(s.get("score") or 0), reverse=True)
    primary = (
        ranked[0]
        if ranked
        else {
            "id": "unknown",
            "classification": "INCONCLUSIVE",
            "score": 0.0,
            "summary": "Insufficient signals.",
        }
    )

    if float(primary.get("score") or 0) < 0.4:
        primary = {
            "id": "client_or_site",
            "classification": "CLIENT_OR_SITE_LIKELY",
            "score": 0.55,
            "summary": (
                "Proxy/DNS/IPv6 signals do not strongly explain breakage. "
                "Run edge-triage (Edge caches, risky extensions, site data; pass "
                "--inprivate works|fails if known), or suspect site-side player/CDN."
            ),
            "next_command": "python -m windows_network_toolkit edge-triage",
        }
        ranked = [primary, *ranked]

    coding_vs_browser = (
        "Coding tools often use IPv4-only or fewer dual-stack third parties; "
        "Edge/Chromium Happy Eyeballs can still stall on AAAA even when prefer-IPv4 is set."
    )

    next_step = {
        "kind": f"investigate_{primary.get('id')}",
        "command": primary.get("next_command"),
        "reason": primary.get("summary"),
    }

    limitations = [
        "Ranked hypothesis is correlation across probes — not proof of a single root cause.",
        "Does not attribute malware, MITM, or intentional attack.",
        "Coding OK while Edge hangs is an expected dual-stack client difference.",
        *DEFAULT_SAFETY_NOTES,
    ]

    return {
        "primary_hypothesis": primary,
        "hypotheses": ranked,
        "coding_vs_browser": coding_vs_browser,
        "operator_next_step": next_step,
        "attack_attribution": {
            "claimed": False,
            "note": (
                "Proxy drift or path failure is observation only. "
                "Attack claims require separate proof tiers "
                "(writer attribution, TLS proof, human review)."
            ),
        },
        "limitations": limitations,
    }


def investigate_why_broken(
    *,
    url: str | None = None,
    proxy: dict[str, Any] | None = None,
    dns: dict[str, Any] | None = None,
    ipv6: dict[str, Any] | None = None,
    url_probe: dict[str, Any] | None = None,
    collect_proxy: HypothesisFn | None = None,
    collect_dns: HypothesisFn | None = None,
    collect_ipv6: HypothesisFn | None = None,
    collect_url: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Read-only multi-signal investigate for browser/connectivity breakage.

    Args:
        url: Optional page URL to probe with curl -4/-6.
        proxy/dns/ipv6/url_probe: Injected snapshots for fixtures/tests.
        collect_*: Optional collectors (defaults call live toolkit modules).

    Returns:
        Governance-enveloped JSON with hypotheses and operator_next_step.
    """
    if (
        platform.system() != "Windows"
        and proxy is None
        and dns is None
        and ipv6 is None
        and url_probe is None
    ):
        return attach_governance_envelope(_unsupported())

    if proxy is None:
        if collect_proxy is not None:
            proxy = collect_proxy()
        else:
            from windows_network_toolkit.diagnostics.proxy import run_proxy_status

            proxy = run_proxy_status()

    if dns is None:
        if collect_dns is not None:
            dns = collect_dns()
        else:
            from windows_network_toolkit.dns_edge import diagnose_dns_edge

            dns = diagnose_dns_edge()

    if ipv6 is None:
        if collect_ipv6 is not None:
            ipv6 = collect_ipv6()
        else:
            from windows_network_toolkit.ipv6_path import investigate_ipv6_path

            ipv6 = investigate_ipv6_path()

    if url and url_probe is None:
        if collect_url is not None:
            url_probe = collect_url(url)
        else:
            url_probe = probe_url_families(url)

    synthesis = synthesize_why_broken(proxy=proxy, dns=dns, ipv6=ipv6, url_probe=url_probe)
    payload = {
        "timestamp_utc": _utc_now(),
        "command": "why-broken",
        "url": url,
        "signals": {
            "proxy_classification": _proxy_signal(proxy).get("classification"),
            "dns_classification": _dns_signal(dns).get("classification"),
            "ipv6_classification": _ipv6_signal(ipv6).get("classification"),
            "url_probe": url_probe,
        },
        "primary_hypothesis": synthesis["primary_hypothesis"],
        "hypotheses": synthesis["hypotheses"],
        "coding_vs_browser": synthesis["coding_vs_browser"],
        "operator_next_step": synthesis["operator_next_step"],
        "attack_attribution": synthesis["attack_attribution"],
        "limitations": synthesis["limitations"],
        "detail": {
            "proxy": {
                "classification": proxy.get("classification") if proxy else None,
            },
            "dns": {
                "classification": dns.get("classification") if dns else None,
                "operator_next_step": (dns or {}).get("operator_next_step"),
            },
            "ipv6": {
                "classification": (
                    ((ipv6 or {}).get("path") or {}).get("classification")
                    or (ipv6 or {}).get("classification")
                ),
                "operator_next_step": (ipv6 or {}).get("operator_next_step"),
                "prefer_ipv4_bit_set": _ipv6_signal(ipv6).get("prefer_ipv4_bit_set"),
            },
        },
    }
    return attach_governance_envelope(payload)

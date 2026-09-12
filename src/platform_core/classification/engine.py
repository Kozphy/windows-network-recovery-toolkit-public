"""Canonical proxy classification engine — primary + secondary signals.

Module responsibility:
    Applies rule-based heuristics to a ``ProxyStateSnapshot`` and optional
    ``ProcessAttribution`` to produce a ``ClassificationResult``-compatible dict
    with a primary classification label, secondary signal list, severity, ordinal
    confidence, reasoning, evidence list, recommended next actions, and
    ``limitations[]``.

System placement:
    Invoked by the ``diagnose`` and ``proxy-status`` CLI commands and the
    ``/platform/classify`` API route.  Depends on
    ``src/platform_core/attribution/classifier.py`` for legacy fallback
    classification and on ``.models`` for the ``PrimaryClassification`` /
    ``SecondarySignal`` enums.  Read-only; no host state is modified.

Key invariants:
    - Classification is a triage label, not a threat verdict; every output path
      carries ``limitations[]`` with explicit epistemic caveats.
    - ``confidence`` is an ordinal float in [0.0, 1.0] clamped by
      ``_clamp_confidence``; it is not a statistical probability.
    - ``POSSIBLE_MITM_RISK`` requires at least two independent indicators; a
      single non-localhost ``ProxyServer`` value yields a medium-confidence label,
      not a confirmed-MITM verdict.
    - ``REVERTER_SUSPECTED`` short-circuits the rest of the ruleset when
      ``reverter_suspected`` or ``repeated_reappearance`` is ``True``.

Side effects:
    None.  Read-only; no registry, file, or network access.

Failure modes:
    If ``proxy`` is ``None`` or ``insufficient_data=True``, the function
    immediately returns an ``ERROR_INSUFFICIENT_DATA`` result with confidence 0.2
    rather than raising.
"""

from __future__ import annotations

import re
from typing import Any

from src.platform_core.attribution.classifier import classify_listener
from src.platform_core.attribution.models import ProcessAttribution, ProxyStateSnapshot

from .models import PrimaryClassification, SecondarySignal

_DEV_NAMES = frozenset(
    {"node.exe", "node", "python.exe", "python", "java.exe", "dotnet.exe", "wsl.exe"}
)
_SECURITY_NAMES = frozenset(
    {"zscaler.exe", "csagent.exe", "forticlient.exe", "vpnagent.exe", "nessusagent.exe"}
)
_SUSPICIOUS_TERMS = re.compile(
    r"(mitm|inject|proxy.?tool|fiddler|charles|burp|socks|tunnel.?proxy)",
    re.I,
)
_LOCALHOST = re.compile(r"127(?:\.\d{1,3}){3}|localhost", re.I)


def _clamp_confidence(value: float) -> float:
    return max(0.0, min(1.0, value))


def classify_proxy(
    proxy: ProxyStateSnapshot | None,
    process: ProcessAttribution | None = None,
    *,
    listener_detected: bool = False,
    registry_rewrite_observed: bool = False,
    writer_listener_mismatch: bool = False,
    repeated_reappearance: bool = False,
    reverter_suspected: bool = False,
    insufficient_data: bool = False,
    proxy_health_status: str | None = None,
) -> dict[str, Any]:
    """Classify the proxy configuration from state and optional process attribution.

    Applies a deterministic priority-ordered ruleset.  All returned dicts carry
    ``limitations[]`` asserting epistemic boundaries (observation ≠ proof,
    classification ≠ accusation).

    Args:
        proxy: Current WinINET/WinHTTP proxy state snapshot.  ``None`` or
            ``insufficient_data=True`` immediately returns
            ``ERROR_INSUFFICIENT_DATA``.
        process: Optional process attribution for the listener on the proxy port.
            Defaults to an empty ``ProcessAttribution`` when not provided.
        listener_detected: Whether a TCP listener was observed on the configured
            proxy port at collection time.
        registry_rewrite_observed: ``True`` when a registry write to the proxy
            keys was detected (e.g. via Sysmon Event 13).
        writer_listener_mismatch: ``True`` when the process that last wrote the
            proxy registry key differs from the process listening on the port.
        repeated_reappearance: ``True`` when proxy settings have reappeared after
            a prior operator-confirmed disable.
        reverter_suspected: Explicit caller signal that a reverter is suspected;
            short-circuits to ``REVERTER_SUSPECTED``.
        insufficient_data: Explicitly signals that inputs are incomplete; overrides
            all other rules.
        proxy_health_status: Optional health-probe status string from
            ``proxy-health`` (e.g. ``"DEAD_LOCALHOST_PROXY"``,
            ``"HEALTHY_LOCALHOST_PROXY"``).

    Returns:
        A ``ClassificationResult``-compatible dict with keys:
        ``primary_classification``, ``secondary_signals``, ``severity``,
        ``confidence``, ``reasoning``, ``evidence``,
        ``recommended_next_actions``, ``limitations``.
    """
    limitations = [
        "Listener classification is correlation, not registry-writer proof.",
        "Publisher/signature absence does not imply malicious intent.",
        "Never claim confirmed MITM without independent proof.",
    ]
    secondary: list[str] = []
    evidence: list[str] = []
    actions: list[str] = []

    if insufficient_data or proxy is None:
        return _result(
            PrimaryClassification.ERROR_INSUFFICIENT_DATA,
            secondary,
            "info",
            0.2,
            "Critical proxy state inputs missing.",
            evidence,
            ["Collect proxy-status and proxy-owner before deciding."],
            limitations + ["Insufficient data — do not remediate automatically."],
        )

    proc = process or ProcessAttribution()
    ps = proxy

    if reverter_suspected or repeated_reappearance:
        if repeated_reappearance:
            secondary.append(SecondarySignal.REPEATED_PROXY_REAPPEARANCE.value)
        return _result(
            PrimaryClassification.REVERTER_SUSPECTED,
            secondary,
            "high",
            0.75,
            "Proxy settings reappeared after prior disable — reverter suspected.",
            evidence + ["Proxy state changed without operator confirmation."],
            ["Run proxy-watch", "Review proxy-writer-attribution with Sysmon if available"],
            limitations,
        )

    if registry_rewrite_observed:
        secondary.append(SecondarySignal.REGISTRY_REWRITE_OBSERVED.value)
    if writer_listener_mismatch:
        secondary.append(SecondarySignal.WRITER_LISTENER_MISMATCH.value)

    wininet_enabled = ps.wininet_proxy_enable == 1
    has_pac = bool(ps.wininet_auto_config_url)
    has_server = bool(ps.wininet_proxy_server)
    is_localhost = bool(_LOCALHOST.search(ps.wininet_proxy_server or ""))
    winhttp_mismatch = wininet_enabled and ps.winhttp_direct_access

    if winhttp_mismatch:
        secondary.append(SecondarySignal.WININET_WINHTTP_MISMATCH.value)
        evidence.append("WinINET enabled while WinHTTP reports direct access.")

    if has_pac:
        secondary.append(SecondarySignal.PAC_PRESENT.value)

    if is_localhost and has_server:
        secondary.append(SecondarySignal.LOCALHOST_PROXY.value)

    # NO_PROXY
    if not wininet_enabled and not has_pac and not has_server:
        return _result(
            PrimaryClassification.NO_PROXY,
            secondary,
            "info",
            0.95,
            "WinINET proxy disabled and no PAC configured.",
            evidence,
            ["No action required."],
            limitations,
        )

    # PAC only path
    if has_pac and not has_server and not wininet_enabled:
        return _result(
            PrimaryClassification.PAC_CONFIGURED,
            secondary,
            "low",
            0.7,
            f"AutoConfigURL configured: {ps.wininet_auto_config_url[:80]}",
            evidence,
            ["Verify PAC URL is expected enterprise policy."],
            limitations,
        )

    port = ps.localhost_port
    if port and wininet_enabled and proxy_health_status:
        if proxy_health_status in ("DEAD_LOCALHOST_PROXY", "DIRECT_ONLY_WORKS"):
            secondary.append(SecondarySignal.DEAD_LOCALHOST_PORT.value)
            return _result(
                PrimaryClassification.DEAD_PROXY_CONFIG,
                secondary,
                "high",
                0.92,
                "Localhost proxy configured but health probes show dead or non-forwarding path.",
                evidence + [f"proxy_health_status={proxy_health_status}"],
                ["Run proxy-health", "Preview proxy-disable with typed confirmation"],
                limitations + ["Dead localhost proxy often causes ERR_PROXY_CONNECTION_FAILED."],
            )
        if proxy_health_status in ("LISTENER_NOT_PROXY", "PROXY_FORWARDING_FAILED"):
            secondary.append(SecondarySignal.UNKNOWN_LISTENER.value)
            return _result(
                PrimaryClassification.UNKNOWN_LOCAL_PROXY,
                secondary,
                "high",
                0.85,
                f"Listener on localhost:{port} does not behave as a working HTTP proxy.",
                evidence + [f"proxy_health_status={proxy_health_status}"],
                ["Run proxy-health", "Human review — correlation only"],
                limitations,
            )
        if proxy_health_status in ("HEALTHY_LOCALHOST_PROXY", "BOTH_DIRECT_AND_PROXY_WORK"):
            secondary.append(SecondarySignal.LOCALHOST_PROXY.value)
            name = (proc.process_name or "").lower()
            sev = "low" if name in _DEV_NAMES else "medium"
            return _result(
                PrimaryClassification.LOCAL_PROXY_ACTIVE,
                secondary,
                sev,
                0.78,
                f"Localhost proxy on port {port} forwards traffic per health probe.",
                evidence + [f"proxy_health_status={proxy_health_status}"],
                ["Run proxy-watch if change was unexpected"],
                limitations,
            )

    if port and wininet_enabled and not listener_detected:
        secondary.append(SecondarySignal.DEAD_LOCALHOST_PORT.value)
        conf = 0.92 if not has_pac else 0.85
        return _result(
            PrimaryClassification.DEAD_PROXY_CONFIG,
            secondary,
            "medium",
            conf,
            f"ProxyServer references localhost:{port} but no listener is bound.",
            evidence + [f"localhost_port={port}", "listener_found=false"],
            [
                "Run diagnose --proof",
                "Preview proxy-disable with typed confirmation if proof supports hypothesis",
            ],
            limitations + ["Dead localhost proxy often causes ERR_PROXY_CONNECTION_FAILED."],
        )

    if listener_detected:
        name = (proc.process_name or "").lower()
        cmd = proc.command_line or ""

        if _SUSPICIOUS_TERMS.search(cmd) or _SUSPICIOUS_TERMS.search(name):
            secondary.append(SecondarySignal.SUSPICIOUS_PROCESS_PATH.value)
            return _result(
                PrimaryClassification.SUSPICIOUS_PROXY,
                secondary,
                "high",
                0.6,
                "Suspicious proxy tooling keywords in process metadata.",
                evidence + [f"process={proc.process_name}"],
                ["Human review required — not a malware verdict"],
                limitations,
            )

        if name in _DEV_NAMES or "dev-server" in cmd.lower() or "webpack" in cmd.lower():
            secondary.append(SecondarySignal.KNOWN_DEV_TOOL.value)
            return _result(
                PrimaryClassification.KNOWN_DEV_PROXY,
                secondary,
                "low",
                0.78,
                f"Development proxy pattern: {proc.process_name}.",
                evidence,
                ["Allow if expected dev workflow."],
                limitations,
            )

        if name in _SECURITY_NAMES:
            secondary.append(SecondarySignal.KNOWN_SECURITY_TOOL.value)
            return _result(
                PrimaryClassification.KNOWN_SECURITY_TOOL,
                secondary,
                "low",
                0.8,
                f"Known security/VPN agent: {proc.process_name}.",
                evidence,
                ["Verify with security team if unexpected."],
                limitations,
            )

        if port:
            secondary.append(SecondarySignal.UNKNOWN_LISTENER.value)
            primary = PrimaryClassification.UNKNOWN_LOCAL_PROXY
            if name in _DEV_NAMES:
                primary = PrimaryClassification.KNOWN_DEV_PROXY
            elif name in _SECURITY_NAMES:
                primary = PrimaryClassification.KNOWN_SECURITY_TOOL
            elif name and name not in ("unknown.exe", "unknown"):
                primary = PrimaryClassification.LOCAL_PROXY_ACTIVE
            return _result(
                primary,
                secondary,
                "low" if primary == PrimaryClassification.LOCAL_PROXY_ACTIVE else "medium",
                0.75 if primary == PrimaryClassification.LOCAL_PROXY_ACTIVE else 0.55,
                f"Localhost listener on port {port} owned by {proc.process_name or 'unknown'}.",
                evidence,
                ["Run proxy-owner", "Run proxy-writer-attribution if Sysmon available"],
                limitations,
            )

    # External proxy — possible MITM indicator (one of two needed)
    mitm_indicators = 0
    if wininet_enabled and has_server and not is_localhost:
        mitm_indicators += 1
        evidence.append(f"Non-localhost ProxyServer: {ps.wininet_proxy_server}")
    if writer_listener_mismatch:
        mitm_indicators += 1
    if registry_rewrite_observed and not listener_detected:
        mitm_indicators += 1

    if mitm_indicators >= 2:
        return _result(
            PrimaryClassification.POSSIBLE_MITM_RISK,
            secondary,
            "high",
            0.65,
            "Multiple independent indicators suggest possible MITM risk — not confirmed.",
            evidence,
            ["Run tls-proof", "Escalate to security team — do not claim confirmed MITM"],
            limitations + ["POSSIBLE_MITM_RISK is hypothesis only."],
        )

    if wininet_enabled and has_server and not is_localhost:
        return _result(
            PrimaryClassification.POSSIBLE_MITM_RISK,
            secondary,
            "medium",
            0.45,
            f"ProxyServer points to non-localhost endpoint: {ps.wininet_proxy_server}.",
            evidence,
            ["Verify expected VPN or corporate gateway policy."],
            limitations,
        )

    # WinINET/WinHTTP mismatch as primary when enabled but no dead port
    if winhttp_mismatch and wininet_enabled and not (port and not listener_detected):
        return _result(
            PrimaryClassification.WININET_WINHTTP_MISMATCH,
            secondary,
            "medium",
            0.72,
            "Browser WinINET path differs from WinHTTP direct configuration.",
            evidence,
            ["Compare browser vs system proxy settings", "Run diagnose --proof"],
            limitations,
        )

    if has_pac and wininet_enabled:
        return _result(
            PrimaryClassification.PAC_CONFIGURED,
            secondary,
            "low",
            0.68,
            "PAC URL present with WinINET proxy enabled.",
            evidence,
            ["Validate PAC script source and enterprise policy."],
            limitations,
        )

    if wininet_enabled:
        secondary.append(SecondarySignal.UNKNOWN_LISTENER.value)
        return _result(
            PrimaryClassification.UNKNOWN_LOCAL_PROXY,
            secondary,
            "medium",
            0.4,
            "Proxy enabled but listener could not be resolved.",
            evidence,
            ["Run proxy-owner", "Re-run with elevated permissions if needed"],
            limitations,
        )

    legacy_cls, rationale, _ = classify_listener(ps, proc, listener_detected=listener_detected)
    return _result(
        PrimaryClassification(legacy_cls.value)
        if legacy_cls.value in PrimaryClassification._value2member_map_
        else PrimaryClassification.ERROR_INSUFFICIENT_DATA,
        secondary,
        "info",
        0.5,
        rationale,
        evidence,
        actions or ["Review proxy-status output"],
        limitations,
    )


def _result(
    primary: PrimaryClassification,
    secondary: list[str],
    severity: str,
    confidence: float,
    reasoning: str,
    evidence: list[str],
    actions: list[str],
    limitations: list[str],
) -> dict[str, Any]:
    return {
        "primary_classification": primary.value,
        "secondary_signals": sorted(set(secondary)),
        "severity": severity,
        "confidence": _clamp_confidence(confidence),
        "reasoning": reasoning,
        "evidence": evidence,
        "recommended_next_actions": actions,
        "limitations": limitations,
    }

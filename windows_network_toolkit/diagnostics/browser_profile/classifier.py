"""Classification rules for browser-profile differentials.

Module responsibility:
    Map observed raw-network baseline, HAR comparison, site-state metadata,
    extension inventory, network preferences, and managed policies into a
    ``BrowserDiffClassification`` label with ordinal confidence and epistemic level.

System placement:
    Called by ``runner.run_browser_diff`` after all evidence is collected.

Key invariants:
    * Output always includes evidence, counter-evidence, assumptions, and next steps.
    * Confidence values are ordinal heuristics — not calibrated probabilities.
    * No system state is read or mutated; classification is pure over supplied models.
    * Observation ≠ proof; correlation ≠ causation; classification ≠ accusation.
"""

from __future__ import annotations

from typing import Any

from windows_network_toolkit.diagnostics.browser_profile.models import (
    BrowserDiffClassification,
    BrowserNetworkPreferenceEvidence,
    BrowserSiteStateEvidence,
    EpistemicLevel,
    HarComparisonEvidence,
    RawNetworkBaseline,
)


def classify_browser_diff(
    *,
    raw: RawNetworkBaseline | dict[str, Any],
    har: HarComparisonEvidence | None,
    site_state: BrowserSiteStateEvidence | dict[str, Any] | None,
    extensions: list[Any] | None,
    network_prefs: BrowserNetworkPreferenceEvidence | dict[str, Any] | None,
    policies: list[Any] | None,
) -> tuple[
    BrowserDiffClassification, float, EpistemicLevel, list[str], list[str], list[str], list[str]
]:
    """Classify browser-profile differential evidence into a triage label.

    Applies a decision-tree to distinguish OS/network failures, browser profile
    state issues, extension interference, service-worker conflicts, proxy/DoH
    mismatches, managed-policy interference, and anti-bot session challenges.

    Args:
        raw: OS/protocol baseline collected without browser cookies or extensions.
            Accepts a validated ``RawNetworkBaseline`` or a raw dict (validated
            internally via Pydantic).
        har: Structural differential of normal vs private browser sessions, or
            ``None`` when no HAR pair has been imported yet.
        site_state: Cookie/service-worker/cache metadata for the target domain from
            the user's default profile, or ``None`` if not collected.
        extensions: List of ``BrowserExtensionEvidence`` records for the profile.
            Pass ``None`` or an empty list when not collected.
        network_prefs: Secure DNS and proxy preferences from the profile's
            Preferences JSON, or ``None`` when not collected.
        policies: List of ``BrowserPolicyEvidence`` records for managed policy keys
            relevant to network or privacy. Pass ``None`` when not collected.

    Returns:
        A 7-tuple of:
            classification (BrowserDiffClassification): Triage label.
            confidence (float): Ordinal heuristic in [0.0, 1.0].
            epistemic_level (EpistemicLevel): Observation / hypothesis / probable_cause / proven_cause.
            evidence (list[str]): Observed facts supporting the classification.
            counter_evidence (list[str]): Facts that weaken the classification.
            assumptions (list[str]): Unverified premises the classification relies on.
            next_steps (list[str]): Safe recommended actions for the operator.
    """
    evidence: list[str] = []
    counter: list[str] = []
    assumptions: list[str] = []
    next_steps: list[str] = []

    if isinstance(raw, dict):
        raw = RawNetworkBaseline.model_validate(raw)

    raw_ok = bool(
        raw.direct_probe_ok
        or (raw.dns_ok and raw.tcp_ok and raw.tls_ok and (raw.http_status or 0) < 500)
    )
    if raw.dns_ok:
        evidence.append("DNS resolution succeeded.")
    else:
        evidence.append("DNS resolution failed.")
    if raw.tcp_ok:
        evidence.append("TCP connection to port succeeded.")
    if raw.tls_ok:
        evidence.append("TLS handshake / certificate inspection succeeded.")
    if raw.direct_probe_ok:
        evidence.append("Direct HTTP request returned a response without browser cookies.")
    if raw.bot_challenge_hint:
        evidence.append(f"Raw probe observed a bot/CDN challenge pattern (HTTP {raw.http_status}).")
    if raw.wininet_proxy_enable == 1 and (raw.winhttp_proxy or "").lower().startswith("direct"):
        evidence.append("WinINET/WinHTTP proxy mismatch observed (orthogonal signal).")
    elif raw.wininet_proxy_enable in (0, None) and (
        raw.winhttp_proxy in (None, "direct") or "direct" in str(raw.winhttp_proxy or "").lower()
    ):
        evidence.append("No WinINET or WinHTTP proxy mismatch was detected.")

    if not raw_ok and (raw.http_status or 0) >= 500:
        return (
            BrowserDiffClassification.SITE_SERVER_FAILURE,
            0.8,
            EpistemicLevel.PROBABLE_CAUSE,
            evidence + [f"HTTP status {raw.http_status} from raw probe."],
            counter,
            assumptions + ["Server error may be transient."],
            ["Retry later; capture HAR if browser still differs."],
        )

    if not raw_ok:
        return (
            BrowserDiffClassification.RAW_NETWORK_FAILURE,
            0.85,
            EpistemicLevel.PROBABLE_CAUSE,
            evidence,
            counter,
            assumptions + ["Browser private-mode success was not required for this class."],
            ["Run proxy-status / tls-proof; prefer-direct preview if localhost proxy present."],
        )

    if har is None:
        next_no_har = [
            "Export normal vs InPrivate HAR and re-run with --import-normal-har/--import-private-har.",
            "Or run browser-profile site-state for the domain.",
        ]
        if raw.bot_challenge_hint:
            next_no_har = [
                "Site may use a CDN/bot challenge (e.g. Cloudflare). Try InPrivate, then clear only this site's data.",
                "Prefer-direct WinINET if a localhost proxy is configured (Node/Cursor common).",
                *next_no_har,
            ]
            return (
                BrowserDiffClassification.ANTI_BOT_SESSION_STATE,
                0.55,
                EpistemicLevel.HYPOTHESIS,
                evidence
                + ["OS/protocol reachability succeeded; challenge may be session-state sensitive."],
                counter,
                assumptions
                + [
                    "No HAR pair yet; challenge attribution is from raw HTTP headers only.",
                    "Did not prove which cookie or fingerprint triggered the challenge.",
                ],
                next_no_har,
            )
        return (
            BrowserDiffClassification.INSUFFICIENT_BROWSER_EVIDENCE,
            0.35,
            EpistemicLevel.OBSERVATION,
            evidence + ["OS/protocol baseline appears healthy."],
            counter,
            assumptions + ["No HAR pair or controlled browser sessions were supplied."],
            next_no_har,
        )

    if har.private_ok:
        evidence.append("Private-session HAR reached the destination.")
    elif har.private_ok is False:
        evidence.append("Private-session HAR failed.")
    if har.normal_ok is False:
        evidence.append("Normal-profile HAR failed.")
    elif har.normal_ok:
        evidence.append("Normal-profile HAR succeeded.")

    for d in har.redirect_diffs:
        evidence.append(f"Redirect sequence differs: {d}")
    for m in har.status_mismatches:
        evidence.append(m)
    if har.blocked_in_normal:
        evidence.append(f"Blocked-by-client requests in normal HAR: {len(har.blocked_in_normal)}.")
    if har.cookie_presence_diff:
        evidence.append(har.cookie_presence_diff)
    if har.auth_challenge_loop_hint:
        evidence.append("Normal HAR shows repeated auth/consent redirects with cookie presence.")
    if har.anti_bot_hint:
        evidence.append("Anti-bot / rate-limit pattern hinted in normal HAR.")

    ss: BrowserSiteStateEvidence | None
    if isinstance(site_state, dict):
        ss = BrowserSiteStateEvidence.model_validate(site_state)
    else:
        ss = site_state
    if ss and ss.cookie_count > 0:
        evidence.append(
            f"The normal profile contained site state for {ss.domain} (cookie_count={ss.cookie_count})."
        )
    if ss and ss.service_worker_count > 0:
        evidence.append(
            f"Service worker artifacts present for domain (count={ss.service_worker_count})."
        )

    proxy_exts = [
        e
        for e in (extensions or [])
        if getattr(e, "looks_like_proxy", False) and getattr(e, "enabled", True)
    ]
    if proxy_exts:
        evidence.append(f"Proxy-capable extension(s) enabled: {len(proxy_exts)}.")

    prefs = network_prefs
    if isinstance(prefs, dict):
        prefs = BrowserNetworkPreferenceEvidence.model_validate(prefs)
    if prefs and (
        prefs.proxy_mode
        or prefs.pac_url
        or (prefs.secure_dns_mode and prefs.secure_dns_mode not in {"off", "automatic", ""})
    ):
        evidence.append(
            f"Profile network preferences: proxy_mode={prefs.proxy_mode!r} doh={prefs.secure_dns_mode!r}."
        )

    if policies:
        evidence.append(f"Managed policy keys relevant to network/privacy: {len(policies)}.")

    # Decision tree
    if har.normal_ok and har.private_ok:
        return (
            BrowserDiffClassification.NO_DIFF_BOTH_OK,
            0.7,
            EpistemicLevel.OBSERVATION,
            evidence,
            counter + ["Both HAR sessions succeeded."],
            assumptions,
            ["If user still sees failures, capture a fresher HAR during the failure."],
        )

    if har.normal_ok is False and har.private_ok is False:
        return (
            BrowserDiffClassification.NO_DIFF_BOTH_FAIL,
            0.65,
            EpistemicLevel.HYPOTHESIS,
            evidence,
            counter,
            assumptions
            + ["Private failure reduces (does not eliminate) profile-only explanations."],
            ["Re-check OS baseline; inspect server/WAF; tls-proof if cert errors."],
        )

    if raw_ok and har.private_ok and har.normal_ok is False:
        primary = BrowserDiffClassification.OS_NETWORK_OK_BROWSER_PROFILE_FAIL
        conf = 0.88
        level = EpistemicLevel.PROBABLE_CAUSE
        next_steps = [
            "Delete only target-domain site data, unregister its service worker, and retry.",
            "Run: wnrt browser-profile repair-preview <domain> --browser <edge|chrome>",
        ]

        if har.blocked_in_normal and not har.blocked_in_private:
            return (
                BrowserDiffClassification.EXTENSION_BLOCKING,
                0.8,
                EpistemicLevel.PROBABLE_CAUSE,
                evidence,
                counter,
                assumptions + ["Blocked URL correlated with normal profile; not malware proof."],
                ["Disable one extension at a time for test; do not wholesale wipe the profile."],
            )

        if har.auth_challenge_loop_hint or (ss and ss.cookie_count > 0 and har.redirect_diffs):
            sub = (
                BrowserDiffClassification.AUTHENTICATION_REDIRECT_LOOP
                if har.auth_challenge_loop_hint
                else BrowserDiffClassification.SITE_DATA_OR_COOKIE_LOOP
            )
            return (
                sub,
                0.84,
                EpistemicLevel.PROBABLE_CAUSE,
                evidence,
                counter,
                assumptions + ["Diagnostic did not inspect cookie values."],
                next_steps,
            )

        if (
            ss
            and ss.service_worker_count > 0
            and any(getattr(x, "service_worker_indicated", False) for x in [])
        ):
            pass
        if ss and ss.service_worker_count > 0:
            # soft preference when SW present and profile fail
            return (
                BrowserDiffClassification.SERVICE_WORKER_INTERFERENCE,
                0.72,
                EpistemicLevel.HYPOTHESIS,
                evidence,
                counter,
                assumptions
                + ["SW presence is correlation, not interception proof without HAR SW flags."],
                ["Unregister domain service workers via repair-preview."],
            )

        if proxy_exts or (prefs and (prefs.proxy_mode not in (None, "system", "direct", ""))):
            return (
                BrowserDiffClassification.PROFILE_PROXY_OR_DOH_MISMATCH,
                0.78,
                EpistemicLevel.HYPOTHESIS,
                evidence,
                counter,
                assumptions,
                ["Compare Secure DNS / proxy extension vs private session."],
            )

        if policies:
            return (
                BrowserDiffClassification.BROWSER_POLICY_INTERFERENCE,
                0.7,
                EpistemicLevel.HYPOTHESIS,
                evidence,
                counter,
                assumptions,
                ["Review managed proxy/DNS/extension policies with IT."],
            )

        if har.anti_bot_hint:
            return (
                BrowserDiffClassification.ANTI_BOT_SESSION_STATE,
                0.75,
                EpistemicLevel.HYPOTHESIS,
                evidence,
                counter,
                assumptions,
                ["Clear site data for domain only; avoid automated retry storms."],
            )

        return (
            primary,
            conf,
            level,
            evidence,
            counter,
            assumptions + ["Specific cookie not identified."],
            next_steps,
        )

    return (
        BrowserDiffClassification.INSUFFICIENT_BROWSER_EVIDENCE,
        0.4,
        EpistemicLevel.OBSERVATION,
        evidence,
        counter,
        assumptions,
        ["Provide both HARs with --proof and re-run."],
    )

"""Website Risk Scoring Engine."""

from __future__ import annotations

import re
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .heuristics import score_local_heuristics, score_url_string_heuristics
from .models import WebsiteRiskLevel, WebsiteRiskResult
from .plugins import ReputationPlugin, run_reputation_plugins
from .urls import MAX_URL_LENGTH, UrlNormalizationError, normalize_url

_SCHEME_PREFIX = re.compile(r"^[a-z][a-z0-9+.\-]*:(?!\d)", re.I)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _probe_url(
    url: str,
    *,
    run: Callable[..., Any],
    timeout: float,
) -> tuple[bool, str, list[str], str, str]:
    """Return https_ok, final_url, redirect_chain, html_excerpt, cert_not_before."""
    argv = [
        "curl",
        "-sS",
        "-L",
        "-w",
        "%{url_effective}\\n%{num_redirects}",
        "--max-time",
        str(int(timeout)),
        "-o",
        "-",
        url if "://" in url else f"https://{url}",
    ]
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout + 5)
        body = proc.stdout or ""
        lines = body.splitlines()
        final_url = url
        num_redirects = 0
        html = body
        if lines:
            # curl -w appends at end; crude split
            m = re.search(r"(https?://\S+)\s*\n(\d+)\s*$", body, re.M)
            if m:
                final_url = m.group(1)
                num_redirects = int(m.group(2))
                html = body[: m.start()]
            else:
                final_url = lines[-1] if lines[-1].startswith("http") else url
        chain = [url]
        if final_url != url:
            chain.append(final_url)
        for _ in range(num_redirects):
            chain.append(final_url)
        https_ok = proc.returncode == 0 and final_url.startswith("https://")
        return https_ok, final_url, chain, html[:4000], ""
    except (OSError, subprocess.TimeoutExpired):
        return False, url, [url], "", ""


def assess_url_static(
    url: str,
    *,
    plugins: list[ReputationPlugin] | None = None,
) -> WebsiteRiskResult:
    """Score a URL from its string alone — never fetched, redirects never followed.

    The URL is canonicalized with ``urls.normalize_url`` and scored with
    ``score_local_heuristics`` (punycode/homograph, suspicious TLD) plus
    ``score_url_string_heuristics`` (shortener, redirect parameter, brand in
    host, user-info, IP host). Used by callers such as email / QR analysis that
    must not contact the target. Reputation plugins run only when passed
    explicitly.
    """
    base_limitations = [
        "Static URL-string analysis only: the URL was not fetched, so HTTPS, "
        "redirects, and page content were not observed.",
        "Shortened links were not resolved.",
        "Heuristic scoring is not antivirus or phishing protection.",
    ]
    has_scheme = _SCHEME_PREFIX.match(url) is not None or url.lower().startswith("www.")
    try:
        normalized = normalize_url(url if has_scheme else f"https://{url}")
    except UrlNormalizationError as exc:
        return WebsiteRiskResult(
            assessment_id=f"wr-{uuid.uuid4().hex[:12]}",
            timestamp_utc=_now(),
            url=url[:MAX_URL_LENGTH],
            final_url="",
            risk_level=WebsiteRiskLevel.UNKNOWN,
            limitations=[
                f"URL could not be normalized ({exc.reason}); not assessed.",
                *base_limitations,
            ],
        )
    target = normalized.url
    score, evidence, _ = score_local_heuristics(
        target,
        https_ok=True,
        final_url=target,
        redirect_chain=[target],
    )
    url_score, url_evidence = score_url_string_heuristics(normalized)
    evidence.extend(url_evidence)
    score = min(1.0, score + url_score)
    used_plugins: list[str] = []
    if plugins:
        rep_evidence, used_plugins = run_reputation_plugins(target, plugins)
        evidence.extend(rep_evidence)
        for ev in rep_evidence:
            score = min(1.0, score + ev.weight)
    if not evidence:
        level = WebsiteRiskLevel.UNKNOWN
    elif score >= 0.65:
        level = WebsiteRiskLevel.HIGH
    elif score >= 0.35:
        level = WebsiteRiskLevel.MEDIUM
    else:
        level = WebsiteRiskLevel.LOW
    return WebsiteRiskResult(
        assessment_id=f"wr-{uuid.uuid4().hex[:12]}",
        timestamp_utc=_now(),
        url=target,
        final_url=target,
        risk_level=level,
        score=round(score, 3),
        evidence=evidence,
        reputation_plugins_used=used_plugins,
        limitations=[
            *base_limitations,
            "No reputation plugin queried."
            if not used_plugins
            else f"Reputation plugins used: {', '.join(used_plugins)}.",
        ],
    )


def run_website_risk(
    url: str,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 20.0,
    inject: dict[str, Any] | None = None,
    plugins: list[ReputationPlugin] | None = None,
) -> WebsiteRiskResult:
    """Score website risk using local heuristics and optional reputation plugins."""
    if inject:
        return WebsiteRiskResult.model_validate(inject)

    run_fn = run or subprocess.run
    target = url if "://" in url else f"https://{url}"
    https_ok, final_url, chain, html, cert_nb = _probe_url(target, run=run_fn, timeout=timeout)

    score, evidence, level = score_local_heuristics(
        target,
        https_ok=https_ok,
        final_url=final_url,
        redirect_chain=chain,
        html_excerpt=html,
        cert_not_before=cert_nb,
    )

    rep_evidence, used_plugins = run_reputation_plugins(target, plugins)
    evidence.extend(rep_evidence)
    for ev in rep_evidence:
        score = min(1.0, score + ev.weight)

    if rep_evidence and score >= 0.65:
        level = WebsiteRiskLevel.HIGH
    elif not https_ok and level == WebsiteRiskLevel.LOW:
        level = WebsiteRiskLevel.UNKNOWN

    limitations = [
        "Heuristic scoring is not antivirus or phishing protection.",
        "No reputation API configured — local heuristics only."
        if not used_plugins
        else f"Reputation plugins used: {', '.join(used_plugins)}.",
        "Redirect chain and HTML analysis are best-effort curl snapshots.",
    ]

    return WebsiteRiskResult(
        assessment_id=f"wr-{uuid.uuid4().hex[:12]}",
        timestamp_utc=_now(),
        url=target,
        final_url=final_url,
        risk_level=level,
        score=round(score, 3),
        evidence=evidence,
        reputation_plugins_used=used_plugins,
        limitations=limitations,
    )

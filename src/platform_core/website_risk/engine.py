"""Website Risk Scoring Engine."""

from __future__ import annotations

import re
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .heuristics import score_local_heuristics
from .models import WebsiteRiskLevel, WebsiteRiskResult
from .plugins import ReputationPlugin, run_reputation_plugins


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
        "curl", "-sS", "-L", "-w", "%{url_effective}\\n%{num_redirects}",
        "--max-time", str(int(timeout)),
        "-o", "-",
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

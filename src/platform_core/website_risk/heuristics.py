"""Local heuristic website risk scoring — no external API required."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urlparse

from .models import WebsiteRiskEvidence, WebsiteRiskLevel

_PUNYCODE = re.compile(r"xn--", re.I)
_HOMOGRAPH = re.compile(r"[^\x00-\x7F]")
_BRAND_TERMS = re.compile(
    r"(paypal|microsoft|apple|google|amazon|netflix|bank|login|sign.?in|verify.?account)",
    re.I,
)
_PAYMENT_FORM = re.compile(
    r"(password|card.?number|cvv|ssn|routing.?number|account.?number)",
    re.I,
)
_SUSPICIOUS_TLD = frozenset({".tk", ".ml", ".ga", ".cf", ".gq", ".zip", ".mov"})


def _redirect_score(chain: list[str]) -> tuple[float, WebsiteRiskEvidence | None]:
    if len(chain) <= 2:
        return 0.0, None
    weight = min(0.4, 0.1 * (len(chain) - 2))
    return weight, WebsiteRiskEvidence(
        signal="excessive_redirects",
        observed=str(len(chain)),
        weight=weight,
        detail="; ".join(chain[:8]),
    )


def score_local_heuristics(
    url: str,
    *,
    https_ok: bool,
    final_url: str,
    redirect_chain: list[str],
    html_excerpt: str = "",
    cert_not_before: str = "",
) -> tuple[float, list[WebsiteRiskEvidence], WebsiteRiskLevel]:
    """Score local heuristics.

    Args:
        url: url supplied by the caller.
        https_ok: https ok supplied by the caller.
        final_url: final url supplied by the caller.
        redirect_chain: redirect chain supplied by the caller.
        html_excerpt: html excerpt supplied by the caller.
        cert_not_before: cert not before supplied by the caller.

    Returns:
        The computed `tuple[float, list[WebsiteRiskEvidence], WebsiteRiskLevel]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    evidence: list[WebsiteRiskEvidence] = []
    score = 0.0

    parsed = urlparse(final_url or url)
    host = parsed.hostname or ""

    if not https_ok:
        score += 0.35
        evidence.append(
            WebsiteRiskEvidence(
                signal="https_failure",
                observed="false",
                weight=0.35,
                detail="HTTPS connection or certificate validation failed.",
            )
        )

    if _PUNYCODE.search(host) or _HOMOGRAPH.search(host):
        score += 0.45
        evidence.append(
            WebsiteRiskEvidence(
                signal="punycode_homograph",
                observed=host,
                weight=0.45,
                detail="Hostname contains punycode or non-ASCII homograph characters.",
            )
        )

    for tld in _SUSPICIOUS_TLD:
        if host.endswith(tld):
            score += 0.25
            evidence.append(
                WebsiteRiskEvidence(
                    signal="suspicious_tld",
                    observed=tld,
                    weight=0.25,
                    detail=f"TLD {tld} is commonly abused in phishing.",
                )
            )
            break

    rw, ev = _redirect_score(redirect_chain)
    if ev:
        score += rw
        evidence.append(ev)

    if html_excerpt:
        if _PAYMENT_FORM.search(html_excerpt):
            score += 0.3
            evidence.append(
                WebsiteRiskEvidence(
                    signal="sensitive_form_fields",
                    observed="detected",
                    weight=0.3,
                    detail="Page excerpt suggests password or payment data collection.",
                )
            )
        if _BRAND_TERMS.search(html_excerpt) and _BRAND_TERMS.search(host) is None:
            score += 0.2
            evidence.append(
                WebsiteRiskEvidence(
                    signal="brand_impersonation_keywords",
                    observed="html_keywords",
                    weight=0.2,
                    detail="Brand/login keywords in page without matching trusted domain.",
                )
            )
        if re.search(r"http://", html_excerpt, re.I) and https_ok:
            score += 0.15
            evidence.append(
                WebsiteRiskEvidence(
                    signal="mixed_content",
                    observed="http_resources_in_html",
                    weight=0.15,
                    detail="Page references insecure HTTP resources.",
                )
            )

    if cert_not_before:
        try:
            nb = datetime.strptime(cert_not_before, "%b %d %H:%M:%S %Y %Z")
            age_days = (datetime.now(UTC).replace(tzinfo=None) - nb).days
            if age_days < 14:
                score += 0.2
                evidence.append(
                    WebsiteRiskEvidence(
                        signal="young_certificate",
                        observed=str(age_days),
                        weight=0.2,
                        detail=f"Certificate issued {age_days} days ago.",
                    )
                )
        except ValueError:
            pass

    if score >= 0.65:
        level = WebsiteRiskLevel.HIGH
    elif score >= 0.35:
        level = WebsiteRiskLevel.MEDIUM
    elif score > 0:
        level = WebsiteRiskLevel.LOW
    else:
        level = WebsiteRiskLevel.LOW
    return min(score, 1.0), evidence, level

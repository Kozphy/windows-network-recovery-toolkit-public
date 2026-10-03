"""Local heuristic website risk scoring — no external API required."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlparse

from .models import WebsiteRiskEvidence, WebsiteRiskLevel
from .urls import NormalizedUrl, is_ip_literal, is_url_shortener, normalize_host, site_label

_PUNYCODE = re.compile(r"xn--", re.I)
_HOMOGRAPH = re.compile(r"[^\x00-\x7F]")
BRAND_NAMES: tuple[str, ...] = ("paypal", "microsoft", "apple", "google", "amazon", "netflix")
_BRAND_TERMS = re.compile(
    r"(" + "|".join(BRAND_NAMES) + r"|bank|login|sign.?in|verify.?account)",
    re.I,
)
# Brand-operated registrable domains whose names differ from the bare brand
# (``microsoftonline.com``) or contain it as a hyphenated token.
BRAND_OWNED_DOMAINS = frozenset(
    {
        "paypal.com",
        "paypal.me",
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "apple.com",
        "icloud.com",
        "google.com",
        "google-analytics.com",
        "googleusercontent.com",
        "gmail.com",
        "youtube.com",
        "amazon.com",
        "amazonaws.com",
        "netflix.com",
    }
)
_REDIRECT_PARAM = re.compile(
    r"^(?:url|u|r|redirect|redirect_?ur[il]|redir|next|target|dest|destination|goto|go|"
    r"continue|return|return_?to|return_?url|returnurl|to|link|out|q)$",
    re.I,
)
_EMBEDDED_URL = re.compile(r"^(?:https?:)?//([^/?#\s]+)", re.I)
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


def _is_brand_owned(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in BRAND_OWNED_DOMAINS)


def _brand_in_host(host: str) -> str | None:
    """Return a brand name used as a whole host token on a non-brand domain."""
    if _is_brand_owned(host):
        return None
    tokens = set(re.split(r"[.\-]", host))
    label = site_label(host)
    for brand in BRAND_NAMES:
        if brand in tokens and label != brand:
            return brand
    return None


def _redirect_target(query: str) -> tuple[str, str] | None:
    """Return ``(param, embedded_host)`` for a redirect-style parameter holding a URL."""
    for key, value in parse_qsl(query, keep_blank_values=False):
        if not _REDIRECT_PARAM.match(key):
            continue
        match = _EMBEDDED_URL.match(value.strip())
        if match:
            return key, normalize_host(match.group(1).rsplit("@", 1)[-1].split(":", 1)[0])
    return None


def score_url_string_heuristics(url: NormalizedUrl) -> tuple[float, list[WebsiteRiskEvidence]]:
    """Score properties visible in the URL string itself (never fetched).

    Complements ``score_local_heuristics`` (punycode/homograph, suspicious TLD,
    redirect chain, page content) for callers that must not contact the
    target: link shorteners, redirect parameters, brand names in unrelated
    hosts, user-info tricks, and raw IP hosts.

    Side effects:
        None. Shortened links are flagged, not resolved.
    """
    evidence: list[WebsiteRiskEvidence] = []
    host = url.host

    if url.has_userinfo:
        evidence.append(
            WebsiteRiskEvidence(
                signal="userinfo_in_url",
                observed="userinfo_present",
                weight=0.3,
                detail=f"Text before '@' disguises the real host ({host}).",
            )
        )
    if is_ip_literal(host):
        evidence.append(
            WebsiteRiskEvidence(
                signal="ip_literal_host",
                observed=host,
                weight=0.2,
                detail="Link points to a raw IP address instead of a domain name.",
            )
        )
    if is_url_shortener(host):
        evidence.append(
            WebsiteRiskEvidence(
                signal="url_shortener",
                observed=host,
                weight=0.15,
                detail="Link shortener hides the destination; it was not resolved.",
            )
        )
    redirect = _redirect_target(url.query)
    if redirect and not _is_brand_owned(host):
        param, target = redirect
        evidence.append(
            WebsiteRiskEvidence(
                signal="open_redirect_parameter",
                observed=target,
                weight=0.15,
                detail=f"Query parameter '{param}' forwards to another host ({target}).",
            )
        )
    brand = None if is_ip_literal(host) else _brand_in_host(host)
    if brand:
        evidence.append(
            WebsiteRiskEvidence(
                signal="brand_impersonation_keywords",
                observed=f"url_host:{brand}",
                weight=0.2,
                detail=f"Brand name '{brand}' appears in a host not operated by that brand.",
            )
        )
    return min(1.0, sum(e.weight for e in evidence)), evidence

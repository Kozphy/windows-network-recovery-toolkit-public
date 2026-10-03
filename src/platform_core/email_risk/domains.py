"""Domain helpers: registrable-domain approximation, lookalike and typo checks.

Key invariants:
    * No DNS, WHOIS, or network lookups — string analysis only.
    * Host normalization and the registrable-domain approximation come from
      ``website_risk.urls`` (single source shared with URL scoring); it uses a
      small multi-label suffix list, not the full Public Suffix List.

Side effects:
    None.
"""

from __future__ import annotations

from typing import Literal

from src.platform_core.website_risk.urls import normalize_host
from src.platform_core.website_risk.urls import registrable_domain as _registrable_host

from .models import EmailRiskConfig

# Single-character confusables collapsed to a canonical skeleton.
_CONFUSABLE_CHARS = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s", "$": "s"})
_CONFUSABLE_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))

SenderRelationship = Literal["internal", "external", "unknown"]


def normalize_domain(value: str) -> str:
    """Lowercase, strip brackets/dots, and IDNA-encode non-ASCII labels when possible."""
    domain = value.strip().strip("<>")
    if "@" in domain:
        domain = domain.rsplit("@", 1)[1]
    return normalize_host(domain)


def registrable_domain(domain: str) -> str:
    """Approximate the registrable domain (eTLD+1); delegates to ``website_risk.urls``."""
    return _registrable_host(normalize_domain(domain))


def domain_label(domain: str) -> tuple[str, str]:
    """Split a registrable domain into ``(label, suffix)``."""
    reg = registrable_domain(domain)
    if "." not in reg:
        return reg, ""
    label, suffix = reg.split(".", 1)
    return label, suffix


def same_or_subdomain(domain: str, parent: str) -> bool:
    """Return True if ``domain`` equals ``parent`` or is a subdomain of it."""
    d, p = normalize_domain(domain), normalize_domain(parent)
    return bool(d and p) and (d == p or d.endswith("." + p))


def is_free_mail(domain: str, config: EmailRiskConfig) -> bool:
    """Return True for consumer mailbox providers (neutral context, not malicious)."""
    d = normalize_domain(domain)
    return any(same_or_subdomain(d, fm) for fm in config.free_mail_domains)


def is_org_domain(domain: str, config: EmailRiskConfig) -> bool:
    """Return True when ``domain`` belongs to a configured organization domain."""
    return any(same_or_subdomain(domain, org) for org in config.organization_domains)


def sender_relationship(domain: str, config: EmailRiskConfig) -> SenderRelationship:
    """Classify the sender as internal / external / unknown relative to the org."""
    if not domain:
        return "unknown"
    if config.organization_domains:
        return "internal" if is_org_domain(domain, config) else "external"
    if is_free_mail(domain, config):
        return "external"
    return "unknown"


def osa_distance(a: str, b: str) -> int:
    """Optimal-string-alignment edit distance (adjacent transpositions count as 1)."""
    if a == b:
        return 0
    rows = len(a) + 1
    cols = len(b) + 1
    dist = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        dist[i][0] = i
    for j in range(cols):
        dist[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dist[i][j] = min(dist[i - 1][j] + 1, dist[i][j - 1] + 1, dist[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                dist[i][j] = min(dist[i][j], dist[i - 2][j - 2] + 1)
    return dist[-1][-1]


def confusable_skeleton(label: str) -> str:
    """Collapse common visual confusables (``rn``→``m``, ``0``→``o``, ``1``→``l``)."""
    skeleton = label.lower()
    for seq, repl in _CONFUSABLE_SEQUENCES:
        skeleton = skeleton.replace(seq, repl)
    return skeleton.translate(_CONFUSABLE_CHARS).replace("-", "")


def protected_domains(config: EmailRiskConfig) -> list[str]:
    """Organization, vendor, and brand domains that impersonators imitate."""
    out: list[str] = []
    for domain in [
        *config.organization_domains,
        *(d for vendor in config.vendors for d in vendor.domains),
        *config.protected_domains,
    ]:
        reg = registrable_domain(domain)
        if reg and reg not in out:
            out.append(reg)
    return out


def lookalike_match(
    domain: str, config: EmailRiskConfig
) -> tuple[Literal["lookalike_domain", "domain_typosquatting"], str, str] | None:
    """Compare ``domain`` against protected domains.

    Returns:
        ``(signal, protected_domain, reason)`` or ``None`` when no resemblance
        was found or the domain *is* a protected domain.
    """
    host = normalize_domain(domain)
    reg = registrable_domain(host)
    if not reg:
        return None
    candidates = protected_domains(config)
    if any(same_or_subdomain(host, p) for p in candidates):
        return None
    if is_free_mail(host, config):
        return None
    owned = {
        registrable_domain(d)
        for d in [*config.organization_domains, *(d for v in config.vendors for d in v.domains)]
    }
    label, suffix = domain_label(reg)
    for protected in candidates:
        p_label, p_suffix = domain_label(protected)
        if not p_label:
            continue
        if host.startswith("xn--") or ".xn--" in host:
            if confusable_skeleton(p_label) in host:
                return (
                    "lookalike_domain",
                    protected,
                    f"Punycode host resembles protected domain {protected}.",
                )
        if label != p_label and confusable_skeleton(label) == confusable_skeleton(p_label):
            return (
                "lookalike_domain",
                protected,
                f"Domain uses visually confusable characters to resemble {protected}.",
            )
        # Brands legitimately operate ccTLD variants (amazon.co.jp), so suffix
        # swaps only count against organization and vendor domains.
        if label == p_label and suffix != p_suffix and protected in owned:
            return (
                "domain_typosquatting",
                protected,
                f"Same name as {protected} under a different suffix (.{suffix}).",
            )
        max_edits = 1 if len(p_label) < 9 else 2
        if len(p_label) >= 4 and 0 < osa_distance(label, p_label) <= max_edits:
            return (
                "domain_typosquatting",
                protected,
                f"Domain label is within {max_edits} edit(s) of {protected}.",
            )
        tokens = [t for t in host.replace("-", ".").split(".") if t]
        if len(p_label) >= 4 and label != p_label and p_label in tokens:
            return (
                "lookalike_domain",
                protected,
                f"Protected name '{p_label}' embedded in unrelated domain {reg}.",
            )
    return None

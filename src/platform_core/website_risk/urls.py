"""URL-string normalization and domain helpers (string analysis only).

Module responsibility:
    Canonicalize URL strings so every caller (``website_risk`` itself, email
    analysis, QR payloads) scores and de-duplicates the same form, and provide
    the registrable-domain approximation shared by URL and email heuristics.

Key invariants:
    * Never resolves, fetches, or follows anything: no DNS, sockets, or
      redirects. Shortened links stay unresolved.
    * Only ``http`` / ``https`` URLs are accepted; other schemes
      (``javascript:``, ``data:``, ``file:`` ...) are rejected with a reason.
    * Path and query are kept verbatim (no unquoting) so the canonical form
      remains forensically faithful; only scheme/host case, default ports,
      invisible characters, surrounding punctuation, and fragments change.
    * Registrable domain uses a small multi-label suffix list, not the full
      Public Suffix List (documented limitation).

Side effects:
    None.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048

MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "com.tw",
        "org.tw",
        "net.tw",
        "edu.tw",
        "gov.tw",
        "idv.tw",
        "com.au",
        "net.au",
        "co.jp",
        "ne.jp",
        "com.cn",
        "com.hk",
        "com.sg",
        "co.kr",
        "com.br",
        "co.nz",
        "co.in",
    }
)

# Link shorteners / QR-redirect services whose destination is hidden until
# followed. They are flagged, never resolved.
URL_SHORTENER_DOMAINS = frozenset(
    {
        "bit.ly",
        "bitly.com",
        "bit.do",
        "tinyurl.com",
        "tiny.cc",
        "t.co",
        "t.ly",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "v.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "s.id",
        "reurl.cc",
        "pse.is",
        "lihi.cc",
        "lihi1.com",
        "lihi.io",
        "qrco.de",
        "qr.codes",
    }
)

_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]")
_LEADING = "<([{\"'`"
_TRAILING = ".,;:!?'\"`)>]}。，；：！？、」』）"
_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}


class UrlNormalizationError(ValueError):
    """Raised when a string cannot be treated as an http(s) URL.

    ``reason`` is a stable token (``non_web_scheme:javascript``,
    ``missing_host``, ``invalid_host``, ``invalid_port``, ``too_long``,
    ``unparseable``, ``empty``).
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class NormalizedUrl:
    """Canonical http(s) URL string plus parsed parts.

    Key fields:
        url: Canonical string used for scoring (userinfo retained because it
            changes where the link goes; callers redact it for display).
        scheme / host / port / path / query: Parsed parts; ``host`` is
            lowercase ASCII (IDNA) without brackets.
        has_userinfo: ``user@`` / ``user:pass@`` present before the host.
        had_invisible_chars: Zero-width / bidi characters were stripped.
    """

    url: str
    scheme: str
    host: str
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    had_invisible_chars: bool

    @property
    def dedupe_key(self) -> str:
        """Key that treats ``https://a.test`` and ``https://a.test/`` as one URL."""
        path = self.path or "/"
        userinfo = "u@" if self.has_userinfo else ""
        port = f":{self.port}" if self.port is not None else ""
        query = f"?{self.query}" if self.query else ""
        return f"{self.scheme}://{userinfo}{self.host}{port}{path}{query}"


def normalize_host(value: str) -> str:
    """Lowercase, strip brackets/trailing dots, and IDNA-encode non-ASCII labels."""
    host = value.strip().strip("[]").lower().rstrip(".")
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def registrable_domain(host: str) -> str:
    """Approximate the registrable domain (eTLD+1) for ``host``; IP literals are returned whole."""
    normalized = normalize_host(host)
    if is_ip_literal(normalized):
        return normalized
    labels = [label for label in normalized.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def site_label(host: str) -> str:
    """Return the name part of the registrable domain (``paypal`` for ``www.paypal.co.uk``)."""
    return registrable_domain(host).split(".", 1)[0]


def is_ip_literal(host: str) -> bool:
    """Return True when ``host`` is an IPv4/IPv6 literal rather than a name."""
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def is_url_shortener(host: str) -> bool:
    """Return True for known link-shortener / QR-redirect hosts."""
    h = normalize_host(host)
    return any(h == s or h.endswith("." + s) for s in URL_SHORTENER_DOMAINS)


def normalize_url(raw: str) -> NormalizedUrl:
    """Canonicalize one URL string without contacting it.

    Raises:
        UrlNormalizationError: not an http(s) URL with a valid host.
    """
    cleaned = _INVISIBLE.sub("", raw or "")
    had_invisible = cleaned != (raw or "")
    candidate = cleaned.strip().lstrip(_LEADING).rstrip(_TRAILING)
    if not candidate:
        raise UrlNormalizationError("empty")
    if len(candidate) > MAX_URL_LENGTH:
        raise UrlNormalizationError("too_long")
    if re.match(r"(?i)www\.", candidate):
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise UrlNormalizationError("unparseable") from exc
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise UrlNormalizationError(f"non_web_scheme:{scheme or 'none'}")
    if any(ch.isspace() for ch in parts.netloc):
        raise UrlNormalizationError("invalid_host")
    raw_host = parts.hostname or ""
    if not raw_host:
        raise UrlNormalizationError("missing_host")
    host = normalize_host(raw_host)
    if not is_ip_literal(host) and not re.fullmatch(r"[a-z0-9.\-_]+", host):
        raise UrlNormalizationError("invalid_host")
    if not is_ip_literal(host) and ("." not in host or ".." in host):
        raise UrlNormalizationError("invalid_host")
    try:
        port = parts.port
    except ValueError as exc:
        raise UrlNormalizationError("invalid_port") from exc
    if port == _DEFAULT_PORTS[scheme]:
        port = None
    userinfo = parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else ""
    host_part = f"[{host}]" if ":" in host else host
    netloc = f"{userinfo + '@' if userinfo else ''}{host_part}{f':{port}' if port else ''}"
    canonical = urlunsplit((scheme, netloc, parts.path, parts.query, ""))
    return NormalizedUrl(
        url=canonical,
        scheme=scheme,
        host=host,
        port=port,
        path=parts.path,
        query=parts.query,
        has_userinfo=bool(userinfo),
        had_invisible_chars=had_invisible,
    )


__all__ = [
    "MAX_URL_LENGTH",
    "MULTI_LABEL_SUFFIXES",
    "URL_SHORTENER_DOMAINS",
    "NormalizedUrl",
    "UrlNormalizationError",
    "is_ip_literal",
    "is_url_shortener",
    "normalize_host",
    "normalize_url",
    "registrable_domain",
    "site_label",
]

"""Normalize domain/URL targets for provenance assessment.

Module responsibility:
    Convert operator input (URL, hostname, trailing dots) into a stable LDH host.

System placement:
    First stage of the domain-provenance pipeline.

Key invariants:
    * Output is lowercase LDH (or empty when invalid).
    * Scheme/path/query/fragment are stripped; ports are dropped.
    * IDN labels are converted via IDNA when possible.

Side effects:
    None.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)

# Second-level labels under ccTLDs that make a compound public suffix (not mapped here).
_COMPOUND_SLD = frozenset({"co", "com", "org", "net", "gov", "ac", "ne", "or", "edu", "gob"})


def normalize_target(raw: str) -> str:
    """Normalize a domain or URL into a lowercase hostname.

    Args:
        raw: User-supplied target (``example.tw``, ``https://example.tw/path``).

    Returns:
        Normalized hostname, or empty string when input cannot be normalized.

    Side effects:
        None.

    Audit Notes:
        Normalization failures should surface as ``INSUFFICIENT`` confidence —
        never invent a host.
    """
    text = (raw or "").strip()
    if not text:
        return ""

    candidate = text
    if "://" in text or text.startswith("//"):
        parsed = urlparse(text if "://" in text else f"https:{text}")
        candidate = parsed.hostname or ""
    else:
        # Strip path/query if pasted without scheme.
        candidate = text.split("/")[0].split("?")[0].split("#")[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[-1]
        if ":" in candidate and not candidate.count(":") > 1:
            # hostname:port (not bare IPv6)
            host_part, _, port = candidate.rpartition(":")
            if port.isdigit():
                candidate = host_part

    candidate = candidate.strip().rstrip(".").lower()
    if not candidate:
        return ""

    try:
        ipaddress.ip_address(candidate)
        return ""
    except ValueError:
        pass

    try:
        # Encode then decode so punycode and unicode IDN both normalize.
        ascii_host = candidate.encode("idna").decode("ascii")
        candidate = ascii_host.lower().rstrip(".")
    except (UnicodeError, UnicodeDecodeError):
        return ""

    if not _HOST_RE.match(candidate):
        # Provenance needs a domain — reject single labels and IPs here.
        return ""

    return candidate


def extract_cctld(host: str) -> str:
    """Return ISO-ish country code from a country-code TLD when applicable.

    Args:
        host: Normalized hostname.

    Returns:
        Uppercase two-letter code for ``.xx`` ccTLDs (e.g. ``TW`` for ``.tw``),
        else empty. Multi-part public suffixes like ``.co.uk`` are not mapped
        to a country here (context-only elsewhere).

    Side effects:
        None.
    """
    parts = [p for p in (host or "").lower().split(".") if p]
    if len(parts) < 2:
        return ""
    tld = parts[-1]
    if len(tld) == 2 and tld.isalpha():
        # Exclude regional / non-single-country codes.
        if tld in {"eu"}:
            return ""
        # Compound public suffixes (e.g. example.co.uk) — do not map.
        if len(parts) >= 3 and parts[-2] in _COMPOUND_SLD:
            return ""
        return tld.upper()
    return ""


def normalize_country(value: str | None) -> str:
    """Normalize a country token to ISO 3166-1 alpha-2 when possible.

    Args:
        value: Raw country string (``TW``, ``Taiwan``, ``tw``).

    Returns:
        Uppercase alpha-2 code or empty string.
    """
    if not value:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    # Common name aliases used in fixtures / RDAP privacy fields.
    aliases = {
        "TAIWAN": "TW",
        "TAIWAN, PROVINCE OF CHINA": "TW",
        "UNITED STATES": "US",
        "UNITED STATES OF AMERICA": "US",
        "USA": "US",
        "JAPAN": "JP",
        "SINGAPORE": "SG",
        "HONG KONG": "HK",
        "CHINA": "CN",
        "KOREA": "KR",
        "REPUBLIC OF KOREA": "KR",
        "GERMANY": "DE",
        "UNITED KINGDOM": "GB",
        "GREAT BRITAIN": "GB",
    }
    upper = text.upper()
    if upper in aliases:
        return aliases[upper]
    if len(text) == 2 and text.isalpha():
        return text.upper()
    # "TW - Taiwan" style
    token = upper.replace("_", " ").split()[0]
    if len(token) == 2 and token.isalpha():
        return token
    return aliases.get(upper, "")

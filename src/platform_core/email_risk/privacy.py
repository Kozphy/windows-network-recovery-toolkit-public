"""Redaction for email-risk outputs.

Key invariants:
    * Email local parts are masked by default; domains are kept because they
      are the primary triage evidence.
    * Long digit runs (account / card / phone numbers) are replaced with a
      length marker.
    * URL query values whose names look like credentials are replaced.
    * Message bodies are never copied into results — only short matched phrases.

Side effects:
    None.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_DIGIT_RUN = re.compile(r"(?<!\d)(?:\d[ \-]?){6,}\d(?!\d)")
_SENSITIVE_QUERY = re.compile(
    r"(token|key|secret|code|session|auth|jwt|sig|password|passwd|otp|email|user)",
    re.IGNORECASE,
)


def mask_address(address: str) -> str:
    """Mask the local part of an address: ``alice@example.com`` → ``a***@example.com``."""
    if "@" not in address:
        return address
    local, domain = address.rsplit("@", 1)
    return f"{local[:1]}***@{domain.lower()}" if local else f"***@{domain.lower()}"


def mask_digits(text: str) -> str:
    """Replace runs of 7+ digits (optionally space/dash separated) with a length marker."""

    def _sub(match: re.Match[str]) -> str:
        digits = re.sub(r"\D", "", match.group(0))
        return f"[digits:{len(digits)}]"

    return _DIGIT_RUN.sub(_sub, text)


def redact_free_text(text: str, *, show_identifiers: bool = False) -> str:
    """Mask digit runs and (unless ``show_identifiers``) embedded email local parts."""
    out = mask_digits(text)
    if not show_identifiers:
        out = _EMAIL_RE.sub(lambda m: mask_address(m.group(0)), out)
    return out


def redact_url(url: str) -> str:
    """Replace credential-like query values and strip URL userinfo."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "[unparseable-url]"
    netloc = parts.netloc.rsplit("@", 1)[-1]
    query = parts.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        query = urlencode(
            [(k, "[REDACTED]" if _SENSITIVE_QUERY.search(k) else v) for k, v in pairs],
            safe="[]",
        )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def stable_hash(value: str) -> str:
    """Short SHA-256 label for correlating identifiers without storing them."""
    if not value:
        return ""
    return "sha256:" + hashlib.sha256(value.strip().encode("utf-8")).hexdigest()[:16]

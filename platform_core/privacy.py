"""Privacy helpers: hash hostnames, mask IPs, redact paths for logs and exports.

Purpose:
    Produce stable redacted strings suitable for JSONL and HTTP responses without storing raw
    hostnames or Windows profile paths.

Safety constraints:
    Functions are pure string transforms—callers remain responsible for not persisting secrets elsewhere.

Notes:
    ``sanitize_domain`` allows a tiny public-probe allowlist; other domains become hashed labels.
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

_PUBLIC_SUFFIX_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "google.com",
        "microsoft.com",
        "cloudflare.com",
        "example.com",
    },
)


def sanitize_hostname(value: str) -> str:
    """Replace a hostname with a short non-reversible hash label.

    Args:
        value: Raw hostname string (may be empty).

    Returns:
        ``host_sha256_<hex>`` or ``[empty]`` when input is blank.

    Raises:
        None.
    """
    if not value or not value.strip():
        return "[empty]"
    digest = hashlib.sha256(value.strip().lower().encode()).hexdigest()[:16]
    return f"host_sha256_{digest}"


def sanitize_username(value: str) -> str:
    """Redact a Windows username for logging.

    Args:
        value: Raw username (may be empty).

    Returns:
        Fixed token ``user_redacted`` or ``[user]`` when empty.

    Raises:
        None.
    """
    if not value or not value.strip():
        return "[user]"
    return "user_redacted"


def sanitize_ip(value: str) -> str:
    """Mask private IPv4; pass loopback through; coarse-mask IPv6 link-local.

    Args:
        value: IP address string.

    Returns:
        Loopback unchanged; RFC1918 IPv4 replaced with coarse buckets; ``fe80:`` as prefix token.

    Raises:
        None.
    """
    s = value.strip()
    if s in {"127.0.0.1", "::1"}:
        return s
    if re.match(r"^10\.\d+\.\d+\.\d+$", s):
        return "10.x.x.x"
    if re.match(r"^192\.168\.\d+\.\d+$", s):
        return "192.168.x.x"
    if re.match(r"^172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+$", s):
        return "172.16-31.x.x"
    if s.startswith("fe80:"):
        return "fe80::/link-local"
    return s


def sanitize_domain(value: str) -> str:
    """Allowlist a small set of probe domains; otherwise emit a hashed token.

    Args:
        value: Domain or hostname-like string.

    Returns:
        Lowercase allowlisted domain, ``[domain]`` when empty, or ``domain_sha256_<hex>``.

    Raises:
        None.
    """
    v = value.strip().lower().rstrip(".")
    if v in _PUBLIC_SUFFIX_ALLOWLIST:
        return v
    if not v:
        return "[domain]"
    h = hashlib.sha256(v.encode()).hexdigest()[:12]
    return f"domain_sha256_{h}"


def stable_endpoint_hash(hostname: str, os_version: str, machine_hint: str | None = None) -> str:
    """Compute a deterministic truncated SHA-256 for a stable endpoint identifier.

    Args:
        hostname: Raw hostname (combined into the hash; not returned).
        os_version: OS version string.
        machine_hint: Optional extra entropy (e.g. install id).

    Returns:
        First 32 hex chars of SHA-256 over joined fields.

    Raises:
        None.

    Safety constraints:
        Does not persist inputs; callers should avoid logging raw ``hostname`` alongside this hash if policy forbids it.
    """
    parts = [hostname, os_version, machine_hint or ""]
    raw = "|".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:32]


def redact_text(text: str) -> str:
    """Redact user profile path segments and coarse-mask private IPv4 in free text.

    Args:
        text: Arbitrary message text.

    Returns:
        Text with ``C:\\Users\\...`` / ``/users/...`` segments and common private IPv4 ranges masked.

    Raises:
        None.
    """
    s = text
    s = re.sub(
        r"(?i)C:\\\\Users\\\\[^\\]+",
        "C:\\\\Users\\\\[redacted]",
        s,
    )
    s = re.sub(
        r"(?i)(/users/)([^/\\s]+)(/)",
        r"\\1[redacted]\\3",
        s,
    )
    s = re.sub(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", "192.168.x.x", s)
    s = re.sub(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "10.x.x.x", s)
    return s

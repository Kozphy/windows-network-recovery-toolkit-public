"""Privacy helpers for evidence, logs, JSONL exports, and HTTP responses.

The public/export boundary is fail-closed: routable IP addresses, endpoint names,
usernames, MAC addresses and common credential forms are not emitted verbatim.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Final

_PUBLIC_SUFFIX_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {"google.com", "microsoft.com", "cloudflare.com", "example.com"}
)
_SECRET_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)\S+"),
    re.compile(
        r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret)\s*[:=]\s*([^\s,;]+)"
    ),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
)
_MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[\w.-]+)?(?![\w:])"
)


def _digest_label(prefix: str, value: str, length: int = 16) -> str:
    digest = hashlib.sha256(value.strip().lower().encode()).hexdigest()[:length]
    return f"{prefix}_sha256_{digest}"


def sanitize_hostname(value: str) -> str:
    """Replace a hostname with a short non-reversible hash label."""
    if not value or not value.strip():
        return "[empty]"
    return _digest_label("host", value)


def sanitize_username(value: str) -> str:
    """Never expose a raw username."""
    return "user_redacted" if value and value.strip() else "[user]"


def sanitize_ip(value: str) -> str:
    """Return a topology-preserving but non-identifying IP classification.

    Loopback is safe to retain. Private/link-local addresses become coarse labels;
    all globally routable or otherwise unclassified addresses are redacted.
    """
    s = value.strip()
    if not s:
        return "[ip]"
    # Windows may append an IPv6 scope id such as %12.
    parse_value = s.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(parse_value)
    except ValueError:
        return "[invalid_ip]"
    if ip.is_loopback:
        return str(ip)
    if isinstance(ip, ipaddress.IPv4Address) and ip.is_private:
        if parse_value.startswith("10."):
            return "10.x.x.x"
        if parse_value.startswith("192.168."):
            return "192.168.x.x"
        if ip in ipaddress.ip_network("172.16.0.0/12"):
            return "172.16-31.x.x"
        return "PRIVATE_IPV4_REDACTED"
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_link_local:
        return "LINK_LOCAL_IPV6_REDACTED"
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_private:
        return "PRIVATE_IPV6_REDACTED"
    return "PUBLIC_IP_REDACTED"


def sanitize_domain(value: str) -> str:
    """Allow known public probe domains; hash every other domain."""
    v = value.strip().lower().rstrip(".")
    if v in _PUBLIC_SUFFIX_ALLOWLIST:
        return v
    if not v:
        return "[domain]"
    return _digest_label("domain", v, 12)


def stable_endpoint_hash(hostname: str, os_version: str, machine_hint: str | None = None) -> str:
    """Compute a deterministic pseudonymous endpoint identifier."""
    raw = "|".join([hostname, os_version, machine_hint or ""]).encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()[:32]


def _redact_secret(match: re.Match[str]) -> str:
    text = match.group(0)
    if text.lower().startswith("authorization"):
        prefix = re.match(r"(?i)(authorization\s*:\s*bearer\s+)", text)
        return (prefix.group(1) if prefix else "Authorization: Bearer ") + "[REDACTED]"
    if "=" in text:
        return text.split("=", 1)[0] + "=[REDACTED]"
    if ":" in text:
        return text.split(":", 1)[0] + ":[REDACTED]"
    return "[SECRET_REDACTED]"


def redact_text(text: str) -> str:
    """Sanitize free-form evidence before persistence, upload, or publication."""
    s = text
    s = re.sub(r"(?i)C:\\Users\\[^\\\s]+", r"C:\\Users\\[redacted]", s)
    s = re.sub(r"(?i)(/users/)([^/\s]+)", r"\1[redacted]", s)
    s = _MAC_RE.sub("[MAC_REDACTED]", s)
    for pattern in _SECRET_PATTERNS:
        s = pattern.sub(_redact_secret, s)

    def ipv4_sub(match: re.Match[str]) -> str:
        return sanitize_ip(match.group(0))

    def ipv6_sub(match: re.Match[str]) -> str:
        candidate = match.group(0)
        # Avoid replacing ordinary punctuation accidentally matched by the permissive IPv6 regex.
        return sanitize_ip(candidate) if candidate.count(":") >= 2 else candidate

    s = _IPV4_RE.sub(ipv4_sub, s)
    s = _IPV6_CANDIDATE_RE.sub(ipv6_sub, s)
    return s


def sanitize_evidence_record(record: dict[str, object]) -> dict[str, object]:
    """Recursively sanitize an evidence payload before it crosses a trust boundary."""
    secret_keys = {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "authorization",
    }
    ip_keys = {"ip", "ip_address", "ipv4", "ipv6", "gateway", "dns_server"}

    def walk(key: str, value: object) -> object:
        k = key.lower()
        if k in secret_keys:
            return "[SECRET_REDACTED]"
        if k in {"hostname", "host"} and isinstance(value, str):
            return sanitize_hostname(value)
        if k in {"username", "user"} and isinstance(value, str):
            return sanitize_username(value)
        if k in {"ssid", "mac", "mac_address"}:
            return "[REDACTED]"
        if k in ip_keys and isinstance(value, str):
            return sanitize_ip(value)
        if isinstance(value, dict):
            return {
                str(child_key): walk(str(child_key), child_value)
                for child_key, child_value in value.items()
            }
        if isinstance(value, list):
            return [walk(k, item) for item in value]
        if isinstance(value, str):
            return redact_text(value)
        return value

    return {str(key): walk(str(key), value) for key, value in record.items()}

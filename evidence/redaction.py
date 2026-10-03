"""Privacy-preserving redaction for evidence exported outside the endpoint.

The redactor is deliberately deterministic: the same sensitive value maps to
one stable token within a configured salt domain. This keeps correlation and
replay useful without publishing raw network identifiers.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Mapping, Sequence
from typing import Any

_IPV4_CANDIDATE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)
_MAC = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")

SENSITIVE_KEYS = frozenset(
    {
        "ip",
        "ip_address",
        "ipv4",
        "ipv6",
        "local_ip",
        "remote_ip",
        "source_ip",
        "destination_ip",
        "public_ip",
        "mac",
        "mac_address",
        "hostname",
        "host_name",
        "computer_name",
        "dns_suffix",
        "vpn_endpoint",
    }
)


def _token(kind: str, value: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}\0{kind}\0{value}".encode()).hexdigest()[:16]
    return f"<{kind}:{digest}>"


def _redact_ip(value: str, salt: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value

    # Loopback and unspecified values are non-identifying and useful in diagnostics.
    if address.is_loopback or address.is_unspecified:
        return value
    return _token("ipv4" if address.version == 4 else "ipv6", address.compressed, salt)


def redact_text(text: str, *, salt: str = "wnrt-public-evidence-v1") -> str:
    """Redact IP/MAC literals embedded in arbitrary diagnostic text."""

    def ipv4(match: re.Match[str]) -> str:
        return _redact_ip(match.group(0), salt)

    def ipv6(match: re.Match[str]) -> str:
        raw = match.group(0)
        return _redact_ip(raw, salt)

    text = _MAC.sub(lambda m: _token("mac", m.group(0).lower(), salt), text)
    text = _IPV4_CANDIDATE.sub(ipv4, text)
    return _IPV6_CANDIDATE.sub(ipv6, text)


def redact_value(value: Any, *, salt: str = "wnrt-public-evidence-v1") -> Any:
    """Recursively sanitize a JSON-compatible evidence value."""

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_KEYS and item is not None:
                if key_text.lower() in {
                    "hostname",
                    "host_name",
                    "computer_name",
                    "dns_suffix",
                    "vpn_endpoint",
                }:
                    sanitized[key_text] = _token("identifier", str(item), salt)
                else:
                    sanitized[key_text] = redact_text(str(item), salt=salt)
            else:
                sanitized[key_text] = redact_value(item, salt=salt)
        return sanitized
    if isinstance(value, str):
        return redact_text(value, salt=salt)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_value(item, salt=salt) for item in value]
    return value


def sanitize_evidence(
    record: Mapping[str, Any], *, salt: str = "wnrt-public-evidence-v1"
) -> dict[str, Any]:
    """Return a sanitized copy suitable for logs, reports, CI artifacts, or GitHub."""

    result = redact_value(record, salt=salt)
    assert isinstance(result, dict)
    return result

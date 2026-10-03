"""IP and sensitive-field redaction for domain provenance outputs.

Module responsibility:
    Redact IP addresses in console/audit JSON by default while preserving
    country codes, timestamps, and non-address evidence.

System placement:
    Applied at the end of the pipeline before print/audit append.

Key invariants:
    * Default posture is redact-on.
    * Timestamps and hostnames are not treated as IPs.
    * Country codes are preserved.

Side effects:
    None — returns new structures.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Keys whose string values should never be IP-redacted (timestamps, ids, etc.).
_SKIP_KEYS = frozenset(
    {
        "timestamp_utc",
        "assessment_id",
        "schema_version",
        "target_raw",
        "target_normalized",
        "detail",
        "mode",
        "confidence_band",
        "decision",
        "id",
        "kind",
        "source",
        "event",
    }
)


def redact_ip(value: str) -> str:
    """Redact a single IP string to a masked form.

    Args:
        value: Candidate IP or mixed text.

    Returns:
        Masked IP (``203.0.113.x`` → ``203.0.113.***``) or original text with
        embedded IPv4 addresses masked. Bare IPv6 literals are masked; time-like
        colon strings are left unchanged.
    """
    text = str(value)
    stripped = text.strip()
    try:
        ip = ipaddress.ip_address(stripped)
        if isinstance(ip, ipaddress.IPv4Address):
            parts = stripped.split(".")
            return ".".join(parts[:3] + ["***"])
        head = stripped.split(":", 1)[0] or "ipv6"
        return f"{head}:***"
    except ValueError:
        pass

    def _mask_v4(match: re.Match[str]) -> str:
        parts = match.group(0).split(".")
        return ".".join(parts[:3] + ["***"])

    return _IPV4_RE.sub(_mask_v4, text)


def redact_structure(obj: Any, *, _key: str | None = None) -> Any:
    """Recursively redact IP-looking strings in JSON-like structures.

    Args:
        obj: Dict/list/scalar payload.
        _key: Parent key name (internal).

    Returns:
        Deep-copied structure with IPs masked.
    """
    if isinstance(obj, dict):
        return {k: redact_structure(v, _key=k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_structure(v, _key=_key) for v in obj]
    if isinstance(obj, str):
        if _key in _SKIP_KEYS:
            return obj
        return redact_ip(obj)
    return obj

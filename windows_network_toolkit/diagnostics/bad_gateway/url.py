"""URL parsing for bad-gateway diagnostics.

Module responsibility:
    Parse http/https target URL into host, port, scheme for probe routing.

Raises:
    ValueError: When scheme is not http/https or host is missing.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class ParsedTarget:
    """Immutable parsed representation of a bad-gateway diagnostic target URL."""

    url: str
    scheme: str
    host: str
    port: int


def parse_target(url: str) -> ParsedTarget:
    """Parse and validate an HTTP/HTTPS target URL into a ``ParsedTarget``.

    Args:
        url: URL string to parse.  Must use ``http`` or ``https`` scheme and
            include a non-empty host component.

    Returns:
        A frozen ``ParsedTarget`` with ``url``, ``scheme``, ``host``, and
        ``port`` (defaulting to 443 for https, 80 for http when absent).

    Raises:
        ValueError: If the scheme is not ``http``/``https`` or the host is empty.
    """
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must use http or https")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("URL must include a host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return ParsedTarget(url=url.strip(), scheme=parsed.scheme, host=host, port=port)

"""Parse and validate localhost diagnostic targets.

Module responsibility:
    Normalize a raw URL string or (host, port, path) triple into a
    ``LocalhostTarget`` dataclass that the diagnose/watch pipeline consumes.
    Validates scheme, port range, and loopback constraint.

System placement:
    Called first by ``localhost/runner.py`` (and ``watch.py``) before any
    probes are started.  Also provides ``filter_response_headers`` used by
    ``http_probe.py`` to strip sensitive response metadata.

Key invariants:
    * Non-loopback hosts are rejected unless ``allow_non_loopback`` is True,
      preventing accidental probing of remote endpoints.
    * Never mutates system state — pure parsing and validation only.
    * ``filter_response_headers`` keeps only a safe, non-sensitive subset of
      headers (content-type, content-length, server, date, cache-control,
      location) to avoid capturing credentials or session tokens.

Side effects:
    None.  Pure functions operating on strings and stdlib types only.

Failure modes:
    ``TargetValidationError`` (a ``ValueError`` subclass) is raised for:
    conflicting args (url + host/port), unsupported scheme, missing host,
    port out of range [1, 65535], or non-loopback target without override.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse


class TargetValidationError(ValueError):
    """Structured validation failure for localhost targets."""

    def __init__(self, message: str, *, code: str = "INVALID_TARGET") -> None:
        """Initialize a localhost target validation error.

        Args:
            message: Human-readable validation failure detail.
            code: Stable machine-readable error code.

        Returns:
            None.

        Side effects:
            Stores ``code`` and ``message`` on the exception instance."""
        super().__init__(message)
        self.code = code
        self.message = message

    def to_dict(self) -> dict[str, str]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {"code": self.code, "message": self.message}


_LOOPBACK_NAMES = frozenset({"localhost", "localhost."})


@dataclass(frozen=True)
class LocalhostTarget:
    """Normalized, immutable loopback HTTP(S) target for a single diagnose/watch run.

    Attributes:
        url: Fully rebuilt URL from normalized components; used for HTTP probes.
        scheme: ``"http"`` or ``"https"``.
        host: Lowercased host string with trailing dot stripped.
        port: Numeric port in [1, 65535].
        path: Path component with leading ``/`` guaranteed.
        query: Raw query string; empty string when absent.
        is_loopback: ``True`` when *host* resolves to a loopback address.
        is_ipv6_literal: ``True`` when *host* is an IPv6 literal (e.g.
            ``"::1"``); drives ``netloc`` bracket insertion in the rebuilt URL.
    """

    url: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    is_loopback: bool
    is_ipv6_literal: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "url": self.url,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "is_loopback": self.is_loopback,
            "is_ipv6_literal": self.is_ipv6_literal,
        }


def is_loopback_host(host: str) -> bool:
    """Return True when *host* is localhost or a loopback IP literal."""

    h = (host or "").strip().lower().rstrip(".")
    if h in _LOOPBACK_NAMES:
        return True
    # Strip brackets for IPv6 literals.
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    try:
        return bool(ipaddress.ip_address(h).is_loopback)
    except ValueError:
        return False


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _normalize_path(path: str | None) -> str:
    if not path:
        return "/"
    return path if path.startswith("/") else f"/{path}"


def parse_localhost_target(
    *,
    url: str | None = None,
    host: str | None = None,
    port: int | None = None,
    path: str | None = None,
    scheme: str = "http",
    allow_non_loopback: bool = False,
) -> LocalhostTarget:
    """Parse URL or host/port/path into a :class:`LocalhostTarget`.

    Raises:
        TargetValidationError: On conflicting args, bad ports, non-loopback without override.
    """

    url_s = (url or "").strip()
    host_s = (host or "").strip()
    path_s = path
    scheme_s = (scheme or "http").strip().lower()

    if url_s and (host_s or port is not None or (path_s is not None and path_s != "")):
        # Allow path-only conflict check: if URL provided, host/port must not also be set.
        if host_s or port is not None:
            raise TargetValidationError(
                "Provide either --url or --host/--port, not both.",
                code="CONFLICTING_ARGS",
            )

    if url_s:
        parsed = urlparse(url_s)
        if parsed.scheme not in {"http", "https"}:
            raise TargetValidationError("URL must use http or https.", code="UNSUPPORTED_SCHEME")
        if not parsed.hostname:
            raise TargetValidationError("URL must include a host.", code="MISSING_HOST")
        scheme_s = parsed.scheme
        host_s = parsed.hostname
        port_v = parsed.port or _default_port(scheme_s)
        path_out = _normalize_path(parsed.path)
        query = parsed.query or ""
    else:
        if not host_s:
            raise TargetValidationError("Either --url or --host is required.", code="MISSING_HOST")
        if scheme_s not in {"http", "https"}:
            raise TargetValidationError("Scheme must be http or https.", code="UNSUPPORTED_SCHEME")
        port_v = int(port) if port is not None else _default_port(scheme_s)
        path_out = _normalize_path(path_s)
        query = ""

    if not (1 <= port_v <= 65535):
        raise TargetValidationError(f"Port out of range: {port_v}", code="INVALID_PORT")

    loopback = is_loopback_host(host_s)
    if not loopback and not allow_non_loopback:
        raise TargetValidationError(
            f"Host '{host_s}' is not loopback. Pass allow_non_loopback only when policy permits.",
            code="NON_LOOPBACK_TARGET",
        )

    is_v6 = False
    try:
        bare = host_s[1:-1] if host_s.startswith("[") and host_s.endswith("]") else host_s
        is_v6 = ipaddress.ip_address(bare).version == 6
    except ValueError:
        is_v6 = False

    netloc = f"[{host_s}]" if is_v6 and not host_s.startswith("[") else host_s
    if (scheme_s == "http" and port_v != 80) or (scheme_s == "https" and port_v != 443):
        netloc = f"{netloc}:{port_v}"
    rebuilt = urlunparse((scheme_s, netloc, path_out, "", query, ""))

    return LocalhostTarget(
        url=rebuilt,
        scheme=scheme_s,
        host=host_s.lower().rstrip("."),
        port=port_v,
        path=path_out,
        query=query,
        is_loopback=loopback,
        is_ipv6_literal=is_v6,
    )


_SAFE_HEADER = re.compile(
    r"^(content-type|content-length|server|date|cache-control|location)$", re.I
)


def filter_response_headers(headers: dict[str, str]) -> dict[str, str]:
    """Keep a small non-sensitive header subset for audit records.

    Retains only: ``content-type``, ``content-length``, ``server``, ``date``,
    ``cache-control``, and ``location``.  All other headers (e.g.
    ``set-cookie``, ``authorization``, ``x-*``) are dropped to avoid
    inadvertently recording session tokens or credentials.

    Args:
        headers: Full response header dict from ``urllib`` response.

    Returns:
        Filtered dict containing only the safe, non-sensitive subset.
    """

    out: dict[str, str] = {}
    for k, v in headers.items():
        if _SAFE_HEADER.match(k):
            out[k] = v
    return out

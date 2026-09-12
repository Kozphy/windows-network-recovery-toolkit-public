"""Pure WinINET ``ProxyServer`` string normalization (no subprocess I/O).

Used by registry readers, CLI summaries, and deterministic scoring. Multi-scheme strings
(``http=``/``https=``/``socks=``) classify into ``ProxyMode`` buckets for audit exports.
"""

from __future__ import annotations

import re

from ..core.models import ParsedProxy, ProxyMode

_HOST_PORT = re.compile(
    r"^(?P<host>[^\s:]+|\[[0-9a-fA-F:.]+\])(?::(?P<port>\d{1,5}))?$",
)
_PAIR = re.compile(
    r"(?P<scheme>[a-zA-Z]+)\s*=\s*(?P<rest>[^;]+)",
)


def _is_local_host(host: str) -> bool:
    h = host.strip().strip("[]").lower()
    return h in {"127.0.0.1", "localhost", "::1"} or h.startswith("127.")


def _mode_from_parts(
    *,
    raw: str | None,
    is_missing: bool,
    is_malformed: bool,
    is_localhost: bool,
    localhost_host: str | None,
    localhost_port: int | None,
    socks_port: int | None,
    http_lp: int | None,
    https_lp: int | None,
    had_multi_scheme: bool,
) -> ProxyMode:
    if is_missing:
        return "missing"
    if is_malformed:
        return "malformed"
    if http_lp is not None or https_lp is not None:
        if is_localhost:
            return "http_https_localhost"
        return "multi_scheme_explicit"
    if socks_port is not None:
        return "socks_localhost" if is_localhost else "multi_scheme_explicit"
    if is_localhost and localhost_port is not None:
        return "manual_localhost"
    if localhost_port is not None:
        return "manual_explicit"
    if raw is not None and not raw.strip():
        return "disabled_server_field"
    return "malformed"


def _parse_host_port_segment(segment: str) -> tuple[str | None, int | None, bool]:
    """Return (host, port, ok)."""
    segment = segment.strip()
    if not segment:
        return None, None, False
    m = _HOST_PORT.match(segment)
    if not m:
        return None, None, False
    host = m.group("host")
    port_s = m.group("port")
    if port_s is None:
        return host, None, False
    try:
        p = int(port_s)
    except ValueError:
        return host, None, False
    if not (1 <= p <= 65535):
        return host, None, False
    return host, p, True


def parse_proxy_server(raw: str | None) -> ParsedProxy:
    """Parse WinINET ``ProxyServer`` string into structured fields.

    Supports ``host:port``, ``http=...;https=...``, and ``socks=host:port`` forms.
    """
    if raw is None:
        return ParsedProxy(
            raw=None,
            is_missing=True,
            is_malformed=False,
            is_localhost_proxy=False,
            localhost_host=None,
            localhost_port=None,
            proxy_mode="missing",
            socks_port=None,
            http_localhost_port=None,
            https_localhost_port=None,
        )

    text = raw.strip()
    if not text:
        return ParsedProxy(
            raw=raw,
            is_missing=True,
            is_malformed=False,
            is_localhost_proxy=False,
            localhost_host=None,
            localhost_port=None,
            proxy_mode="missing",
            socks_port=None,
            http_localhost_port=None,
            https_localhost_port=None,
        )

    pairs = list(_PAIR.finditer(text))
    if pairs:
        socks_port: int | None = None
        http_lp: int | None = None
        https_lp: int | None = None
        localhost_host: str | None = None
        localhost_port: int | None = None
        is_localhost = False
        any_ok = False
        for pm in pairs:
            scheme = pm.group("scheme").lower()
            rest = pm.group("rest").strip()
            host, port, ok = _parse_host_port_segment(rest)
            if not ok or host is None or port is None:
                continue
            any_ok = True
            if _is_local_host(host):
                is_localhost = True
                localhost_host = host.strip("[]")
                localhost_port = localhost_port or port
            if scheme == "socks":
                socks_port = port
            elif scheme == "http":
                http_lp = port
            elif scheme == "https":
                https_lp = port

        if not any_ok:
            return ParsedProxy(
                raw=raw,
                is_missing=False,
                is_malformed=True,
                is_localhost_proxy=False,
                localhost_host=None,
                localhost_port=None,
                proxy_mode="malformed",
                socks_port=None,
                http_localhost_port=None,
                https_localhost_port=None,
            )

        primary_port = (
            localhost_port
            or https_lp
            or http_lp
            or socks_port
        )
        mode = _mode_from_parts(
            raw=raw,
            is_missing=False,
            is_malformed=False,
            is_localhost=is_localhost,
            localhost_host=localhost_host,
            localhost_port=primary_port,
            socks_port=socks_port,
            http_lp=http_lp,
            https_lp=https_lp,
            had_multi_scheme=len(pairs) > 1,
        )
        display_local_port = primary_port if is_localhost else None
        return ParsedProxy(
            raw=raw,
            is_missing=False,
            is_malformed=False,
            is_localhost_proxy=is_localhost,
            localhost_host=localhost_host,
            localhost_port=display_local_port,
            proxy_mode=mode,
            socks_port=socks_port,
            http_localhost_port=http_lp,
            https_localhost_port=https_lp,
        )

    host, port, ok = _parse_host_port_segment(text)
    if ok and host is not None and port is not None:
        is_localhost = _is_local_host(host)
        localhost_host = host.strip("[]") if is_localhost else None
        mode = _mode_from_parts(
            raw=raw,
            is_missing=False,
            is_malformed=False,
            is_localhost=is_localhost,
            localhost_host=localhost_host,
            localhost_port=port,
            socks_port=None,
            http_lp=None,
            https_lp=None,
            had_multi_scheme=False,
        )
        return ParsedProxy(
            raw=raw,
            is_missing=False,
            is_malformed=False,
            is_localhost_proxy=is_localhost,
            localhost_host=localhost_host,
            localhost_port=port,
            proxy_mode=mode,
            socks_port=None,
            http_localhost_port=None,
            https_localhost_port=None,
        )

    return ParsedProxy(
        raw=raw,
        is_missing=False,
        is_malformed=True,
        is_localhost_proxy=False,
        localhost_host=None,
        localhost_port=None,
        proxy_mode="malformed",
        socks_port=None,
        http_localhost_port=None,
        https_localhost_port=None,
    )


def summarize_proxy_risk(parsed: ParsedProxy, proxy_enable_is_on: bool) -> str:
    """Return low/medium/high risk label (diagnostic sense only)."""
    if not proxy_enable_is_on:
        return "low"
    if parsed.is_localhost_proxy:
        return "high"
    if parsed.proxy_mode in {"manual_explicit", "multi_scheme_explicit", "socks_localhost"}:
        return "medium"
    if parsed.is_malformed:
        return "medium"
    return "low"

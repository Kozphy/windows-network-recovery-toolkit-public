"""HTTP-layer probes for localhost targets (direct vs proxy-aware).

Module responsibility:
    Issue bounded GET requests to a localhost URL in two modes — with proxies
    explicitly suppressed (``direct``) and with the system/explicit proxy
    applied (``proxy_aware``) — to produce evidence about whether a proxy is
    interfering with loopback access.

System placement:
    Called by ``localhost/runner.py`` only after at least one TCP probe
    succeeds (HTTP probes are skipped when TCP entirely fails).  Uses stdlib
    ``urllib`` only; no third-party HTTP clients.

Key invariants:
    * Response bodies are never stored; only status code, headers, and
      elapsed time are kept, to avoid inadvertently capturing sensitive data.
    * ``filter_response_headers`` from ``target.py`` limits stored headers to
      a safe non-sensitive subset.
    * ``success`` is defined as ``200 <= status_code < 500`` so 3xx/4xx still
      contribute to proxy-comparison logic.
    * Redirect following is intentionally disabled (``_NoRedirect`` handler).

Side effects:
    Establishes real TCP connections when called with live URLs.  No files
    are written; no OS state is modified.

Failure modes:
    All exceptions (``URLError``, ``TimeoutError``, ``OSError``, ``ValueError``)
    are caught and mapped to ``exception_category`` in the result.  The probe
    always returns an ``HttpProbeResult`` — never raises.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from .target import filter_response_headers


@dataclass
class HttpProbeResult:
    """Evidence record for a single HTTP GET probe attempt.

    Attributes:
        mode: Probe strategy — ``"direct"`` (proxies suppressed) or
            ``"proxy_aware"`` (system/explicit proxy applied).
        requested_url: The URL as supplied to the opener.
        effective_url: Final URL after any redirect; ``None`` when the
            request did not complete.
        status_code: HTTP status integer, or ``None`` on connection failure.
        response_headers: Filtered subset of response headers (non-sensitive
            keys only — see ``filter_response_headers``).
        elapsed_ms: Wall-clock time from connection open to body read, in ms.
        redirect_chain: Intermediate redirect URLs (currently empty; redirect
            following is disabled by ``_NoRedirect``).
        tls_info: Minimal TLS metadata for ``https`` URLs; ``None`` for plain
            HTTP or when negotiation details are unavailable.
        exception_category: Normalized error category string when the request
            failed (e.g. ``"CONNECTION_REFUSED"``, ``"TIMEOUT"``).
        detail: Short human-readable description of the outcome.
        success: True when ``200 <= status_code < 500``.
        timestamp_utc: ISO-8601 UTC timestamp at probe start.
    """

    mode: str  # direct | proxy_aware
    requested_url: str
    effective_url: str | None = None
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    redirect_chain: list[str] = field(default_factory=list)
    tls_info: dict[str, Any] | None = None
    exception_category: str | None = None
    detail: str = ""
    success: bool = False
    timestamp_utc: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "mode": self.mode,
            "requested_url": self.requested_url,
            "effective_url": self.effective_url,
            "status_code": self.status_code,
            "response_headers": dict(self.response_headers),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "redirect_chain": list(self.redirect_chain),
            "tls_info": self.tls_info,
            "exception_category": self.exception_category,
            "detail": self.detail,
            "success": self.success,
            "timestamp_utc": self.timestamp_utc,
        }


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _categorize_http_exc(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "TIMEOUT"
    if isinstance(exc, urllib.error.HTTPError):
        return "HTTP_ERROR"
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ConnectionRefusedError) or "refused" in str(exc).lower():
            return "CONNECTION_REFUSED"
        if isinstance(reason, TimeoutError) or "timed out" in str(exc).lower():
            return "TIMEOUT"
        return "URL_ERROR"
    if isinstance(exc, ConnectionRefusedError):
        return "CONNECTION_REFUSED"
    if isinstance(exc, OSError):
        return "OS_ERROR"
    return "UNKNOWN"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        """Disable urllib redirect following for HTTP probes.

        Args:
            req: Original urllib request object.
            fp: Response file-like object.
            code: Redirect status code.
            msg: Redirect status message.
            headers: Redirect response headers.
            newurl: Target URL from the redirect.

        Returns:
            ``None`` so urllib surfaces the redirect instead of following it.

        Side effects:
            None."""
        return None


def http_probe_direct(url: str, *, timeout: float = 2.0) -> HttpProbeResult:
    """GET *url* with proxies explicitly disabled; does not store response bodies.

    Uses an empty ``ProxyHandler({})`` to bypass all system proxy settings,
    isolating network-layer reachability from proxy configuration.

    Args:
        url: The target URL (must be http or https).
        timeout: Connection + read timeout in seconds.

    Returns:
        ``HttpProbeResult`` with ``mode="direct"``.  Always returns; never
        raises — exceptions are captured in ``exception_category``.

    Side effects:
        Establishes a TCP connection to *url*'s host when reachable.
    """

    result = HttpProbeResult(mode="direct", requested_url=url, timestamp_utc=_now())
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, method="GET")
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect,
        )
        with opener.open(req, timeout=timeout) as resp:
            result.elapsed_ms = (time.perf_counter() - start) * 1000.0
            result.status_code = int(resp.status)
            result.effective_url = str(resp.geturl())
            result.response_headers = filter_response_headers(
                {k: v for k, v in resp.headers.items()}
            )
            result.success = 200 <= result.status_code < 500
            result.detail = f"Direct GET status={result.status_code}"
            if urlparse(url).scheme == "https":
                result.tls_info = {
                    "scheme": "https",
                    "note": "TLS negotiated; certificate details not collected by default.",
                }
            return result
    except urllib.error.HTTPError as exc:
        result.elapsed_ms = (time.perf_counter() - start) * 1000.0
        result.status_code = int(exc.code)
        result.exception_category = "HTTP_ERROR"
        result.detail = f"HTTPError {exc.code}"
        # 3xx from no-redirect handler surfaces here sometimes
        result.success = 200 <= result.status_code < 500
        if exc.headers:
            result.response_headers = filter_response_headers(
                {k: v for k, v in exc.headers.items()}
            )
        return result
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        result.elapsed_ms = (time.perf_counter() - start) * 1000.0
        result.exception_category = _categorize_http_exc(exc)
        result.detail = str(exc)[:300]
        return result


def http_probe_proxy_aware(
    url: str,
    *,
    timeout: float = 2.0,
    proxy_url: str | None = None,
) -> HttpProbeResult:
    """GET *url* through the system proxy env or an explicit proxy URL.

    When *proxy_url* is ``None``, the default ``urllib`` opener is used, which
    picks up ``http_proxy`` / ``https_proxy`` environment variables and any
    platform proxy settings visible to Python.  When *proxy_url* is set, an
    explicit ``ProxyHandler`` is constructed with that URL for both http and
    https schemes.

    This probe is paired with ``http_probe_direct`` to identify whether a
    proxy is interfering with loopback access: if direct succeeds and
    proxy-aware fails, that is *possible* interference (not proof).

    Args:
        url: The target URL.
        timeout: Connection + read timeout in seconds.
        proxy_url: Optional explicit proxy URL (``http://host:port``).

    Returns:
        ``HttpProbeResult`` with ``mode="proxy_aware"``.  Always returns;
        never raises.

    Side effects:
        May route traffic through a system or explicit proxy if configured.
    """

    result = HttpProbeResult(mode="proxy_aware", requested_url=url, timestamp_utc=_now())
    start = time.perf_counter()
    try:
        req = urllib.request.Request(url, method="GET")
        if proxy_url:
            handlers = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
            opener = urllib.request.build_opener(handlers, _NoRedirect)
        else:
            # Default opener honors environment / system proxy settings where available
            opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=timeout) as resp:
            result.elapsed_ms = (time.perf_counter() - start) * 1000.0
            result.status_code = int(resp.status)
            result.effective_url = str(resp.geturl())
            result.response_headers = filter_response_headers(
                {k: v for k, v in resp.headers.items()}
            )
            result.success = 200 <= result.status_code < 500
            result.detail = f"Proxy-aware GET status={result.status_code}"
            return result
    except urllib.error.HTTPError as exc:
        result.elapsed_ms = (time.perf_counter() - start) * 1000.0
        result.status_code = int(exc.code)
        result.exception_category = "HTTP_ERROR"
        result.detail = f"HTTPError {exc.code}"
        result.success = 200 <= result.status_code < 500
        return result
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        result.elapsed_ms = (time.perf_counter() - start) * 1000.0
        result.exception_category = _categorize_http_exc(exc)
        result.detail = str(exc)[:300]
        return result


def compare_http_probes(direct: HttpProbeResult, proxy_aware: HttpProbeResult) -> dict[str, Any]:
    """Summarize whether the direct and proxy-aware probe outcomes differ.

    Computes a simple boolean ``differ`` flag and an ``interpretation`` string
    that is intentionally cautious: difference alone is not proof of proxy
    interference.  Both probes failing is treated as proxy-unrelated.

    Args:
        direct: Result from ``http_probe_direct``.
        proxy_aware: Result from ``http_probe_proxy_aware``.

    Returns:
        Dict with keys ``differ``, ``direct_success``, ``proxy_aware_success``,
        and ``interpretation``.  Embedded in the ``proxy_comparison`` field of
        the diagnose report.
    """

    differ = (
        direct.success != proxy_aware.success
        or direct.status_code != proxy_aware.status_code
        or direct.exception_category != proxy_aware.exception_category
    )
    return {
        "differ": differ,
        "direct_success": direct.success,
        "proxy_aware_success": proxy_aware.success,
        "interpretation": (
            "Direct and proxy-aware results differ — proxy path may interfere."
            if differ and direct.success and not proxy_aware.success
            else "Paths agree or both failed — proxy interference not uniquely supported."
            if not differ or (not direct.success and not proxy_aware.success)
            else "Results differ; review both probes before concluding proxy interference."
        ),
    }

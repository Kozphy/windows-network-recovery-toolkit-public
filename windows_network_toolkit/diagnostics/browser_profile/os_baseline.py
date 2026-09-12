"""OS/protocol baseline probe — no browser cookies or extensions.

Module responsibility:
    Collect DNS resolution, TCP connectivity, TLS certificate inspection, and
    direct vs system-proxy HTTP probe results for a target URL without involving
    any browser profile state (cookies, extensions, or managed policies).

System placement:
    Called by ``runner.run_browser_diff`` as the first evidence-collection step.
    Also used standalone by the ``proxy-status`` CLI path.

Key invariants:
    * All probes use Python's ``socket`` / ``ssl`` / ``urllib`` — no browser binary.
    * Successful raw probe does not prove the browser profile is healthy.
    * ``inject`` dict skips live I/O for deterministic tests.
    * WinINET / WinHTTP registry reads are best-effort (Windows-only; silent on Linux).

Side effects:
    * Outbound DNS, TCP, and HTTP I/O when ``inject`` is not supplied.
    * Read-only registry access on Windows via ``winreg``.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import ProxyHandler, Request, build_opener

from windows_network_toolkit.diagnostics.browser_profile.models import (
    EvidenceMeta,
    RawNetworkBaseline,
    ReliabilityTier,
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_wininet() -> tuple[int | None, str | None, bool]:
    try:
        import winreg

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        )
        enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            server = None
        try:
            pac, _ = winreg.QueryValueEx(key, "AutoConfigURL")
            pac_on = bool(pac)
        except FileNotFoundError:
            pac_on = False
        winreg.CloseKey(key)
        return int(enable), str(server) if server else None, pac_on
    except OSError:
        return None, None, False


def _read_winhttp(run: Callable[..., Any]) -> str | None:
    try:
        proc = run(
            ["netsh", "winhttp", "show", "proxy"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        for line in text.splitlines():
            if "Proxy Server" in line or "proxy server" in line.lower():
                return line.strip()
        if "Direct access" in text:
            return "direct"
        return text.strip()[:200] or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def collect_raw_network_baseline(
    url: str,
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: dict[str, Any] | None = None,
) -> RawNetworkBaseline:
    """Collect DNS/TCP/TLS/HTTP and proxy-stack evidence without browser state.

    Performs, in order:
    * DNS resolution via ``socket.getaddrinfo``.
    * TCP connectivity to the resolved address.
    * TLS handshake and certificate inspection (HTTPS targets only).
    * Direct HTTP probe (bypassing environment proxy) and system-proxy HTTP probe.
    * WinINET/WinHTTP proxy registry reads (Windows only).

    Args:
        url: Target URL or bare hostname.  ``https://`` is prepended if no scheme
            is present.
        run: Injectable subprocess callable (e.g. ``subprocess.run``).  Defaults to
            ``subprocess.run`` when ``None``.  Used only for the WinHTTP read.
        timeout: Per-probe socket / HTTP timeout in seconds (default 15.0).
        inject: If supplied, the dict is validated directly as a
            ``RawNetworkBaseline`` and all live I/O is skipped.  Used in tests.

    Returns:
        A ``RawNetworkBaseline`` with DNS/TCP/TLS/HTTP results, WinINET/WinHTTP
        state, environment-proxy variables, bot-challenge hint, and a
        ``limitations`` list describing collection boundaries.
    """
    if inject:
        return RawNetworkBaseline.model_validate(inject)

    run_fn = run or subprocess.run
    target = url if "://" in url else f"https://{url}"
    parsed = urlparse(target)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    ipv4: list[str] = []
    ipv6: list[str] = []
    dns_ok = False
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        for fam, *_rest, sockaddr in infos:
            addr = sockaddr[0]
            if fam == socket.AF_INET:
                ipv4.append(addr)
            elif fam == socket.AF_INET6:
                ipv6.append(addr)
        dns_ok = bool(ipv4 or ipv6)
    except OSError as exc:
        dns_err = str(exc)
    else:
        dns_err = None

    tcp_ok = False
    tcp_error = None
    if dns_ok:
        try:
            with socket.create_connection((ipv4[0] if ipv4 else host, port), timeout=timeout):
                tcp_ok = True
        except OSError as exc:
            tcp_error = str(exc)

    tls_ok = False
    tls_error = None
    cert_subject = cert_issuer = cert_nb = cert_na = thumb = None
    sans: list[str] = []
    chain_ok = None
    if parsed.scheme == "https" and tcp_ok:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection(
                (ipv4[0] if ipv4 else host, port), timeout=timeout
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    tls_ok = True
                    der = ssock.getpeercert(binary_form=True)
                    cert = ssock.getpeercert()
                    if der:
                        thumb = hashlib.sha256(der).hexdigest()
                    if cert:
                        subj = cert.get("subject") or ()
                        iss = cert.get("issuer") or ()
                        cert_subject = ",".join("=".join(x) for t in subj for x in t)
                        cert_issuer = ",".join("=".join(x) for t in iss for x in t)
                        cert_nb = cert.get("notBefore")
                        cert_na = cert.get("notAfter")
                        for typ, val in cert.get("subjectAltName") or ():
                            if typ == "DNS":
                                sans.append(val)
                    chain_ok = True
        except ssl.SSLError as exc:
            tls_error = str(exc)
            chain_ok = False
        except OSError as exc:
            tls_error = str(exc)

    def _bot_hint_from_headers(status: int, headers: Any) -> bool:
        if not headers:
            return False
        items = {str(k).lower(): str(v) for k, v in headers.items()}
        mit = (items.get("cf-mitigated") or "").lower()
        server = (items.get("server") or "").lower()
        if "challenge" in mit:
            return True
        return "cloudflare" in server and status in {403, 429, 503}

    def _http_probe(
        use_env_proxy: bool,
    ) -> tuple[bool, int | None, list[str], float | None, str | None, bool]:
        t0 = time.perf_counter()
        handlers = []
        if not use_env_proxy:
            handlers.append(ProxyHandler({}))
        opener = build_opener(*handlers)
        req = Request(target, method="GET", headers={"User-Agent": "WNRT-raw-probe/1.0"})
        chain = [target]
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                final = resp.geturl()
                if final and final != target:
                    chain.append(final)
                ver = getattr(resp, "version", None)
                http_ver = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(ver, str(ver) if ver else None)
                bot = _bot_hint_from_headers(status, resp.headers)
                return True, status, chain, (time.perf_counter() - t0) * 1000.0, http_ver, bot
        except HTTPError as exc:
            code = int(exc.code)
            bot = _bot_hint_from_headers(code, exc.headers)
            return True, code, chain, (time.perf_counter() - t0) * 1000.0, None, bot
        except (URLError, OSError, TimeoutError):
            return False, None, chain, (time.perf_counter() - t0) * 1000.0, None, False

    direct_ok, status_d, chain_d, timing_d, http_ver, bot_d = _http_probe(False)
    sys_ok, status_s, chain_s, timing_s, _, bot_s = _http_probe(True)

    we, ws, pac = _read_wininet()
    wh = _read_winhttp(run_fn)

    limitations = [
        "Raw probe uses urllib without browser cookies or extensions.",
        "Successful probe does not prove browser profiles are healthy.",
    ]
    if dns_err:
        limitations.append(f"DNS error: {dns_err}")
    if bot_d or bot_s:
        limitations.append(
            "HTTP response hints at a bot/CDN challenge (e.g. Cloudflare). "
            "Raw TCP/TLS success does not mean a browser session will pass the challenge."
        )

    return RawNetworkBaseline(
        target_url=target,
        dns_ok=dns_ok,
        ipv4_addresses=sorted(set(ipv4)),
        ipv6_addresses=sorted(set(ipv6)),
        tcp_ok=tcp_ok,
        tcp_error=tcp_error,
        tls_ok=tls_ok,
        tls_error=tls_error,
        cert_subject=cert_subject,
        cert_issuer=cert_issuer,
        cert_sans=sans,
        cert_not_before=cert_nb,
        cert_not_after=cert_na,
        cert_thumbprint_sha256=thumb,
        cert_chain_ok=chain_ok,
        http_status=status_d if direct_ok else status_s,
        redirect_chain=chain_d if direct_ok else chain_s,
        timing_ms=timing_d if direct_ok else timing_s,
        http_version=http_ver,
        wininet_proxy_enable=we,
        wininet_proxy_server=ws,
        winhttp_proxy=wh,
        pac_configured=pac,
        env_http_proxy=os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"),
        env_https_proxy=os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"),
        env_no_proxy=os.environ.get("NO_PROXY") or os.environ.get("no_proxy"),
        direct_probe_ok=direct_ok,
        system_proxy_probe_ok=sys_ok,
        bot_challenge_hint=bool(bot_d or bot_s),
        meta=EvidenceMeta(
            source="os_baseline",
            collected_at_utc=_now(),
            collection_method="socket_ssl_urllib",
            reliability_tier=ReliabilityTier.T2_RUNTIME_CORROBORATION,
        ),
        limitations=limitations,
    )

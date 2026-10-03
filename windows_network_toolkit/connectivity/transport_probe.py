"""Run family-specific read-only TCP/TLS/HTTP probes.

This module is the transport stage after DNS and route collection. It selects
one address family, opens an outbound TCP connection, negotiates TLS with the
system trust store, and sends a bounded ``HEAD`` request. It does not mutate
Windows or network configuration and does not authorize remediation.

The returned evidence distinguishes transport stages. A failed TLS or HTTP
check preserves a successful TCP result while marking later stages as failed
or not tested, allowing callers to audit where the path stopped.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass

from .dual_stack import PathState


@dataclass(frozen=True, slots=True)
class TransportEvidence:
    """Immutable results from one family-specific HTTPS probe.

    Attributes:
        tcp: Whether the TCP connection was established.
        tls: Whether the TLS handshake completed.
        http: Whether the response began with an HTTP status line.
        endpoint: Whether the endpoint returned an HTTP-shaped response.
        latency_ms: Elapsed probe time when a connection attempt was made.
        address: Selected destination address, when resolution succeeded.
        limitations: Human-readable failure or evidence-gap details.
    """

    tcp: PathState
    tls: PathState
    http: PathState
    endpoint: PathState
    latency_ms: float | None
    address: str | None
    limitations: tuple[str, ...] = ()


def _validate_family(family: int) -> None:
    """Reject address-family selectors other than IPv4 or IPv6."""
    if family not in (4, 6):
        raise ValueError(f"family must be 4 or 6, got {family!r}")


def _tls_client_context() -> ssl.SSLContext:
    """Build a TLS 1.2+ client context with system trust certificates."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Explicitly disable legacy protocols for static analyzers that do not
    # fully model minimum_version assignments.
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    context.load_default_certs()
    return context


def probe_https(
    host: str,
    family: int,
    *,
    port: int = 443,
    timeout: float = 5.0,
    path: str = "/",
) -> TransportEvidence:
    """Probe HTTPS using an explicitly selected IPv4 or IPv6 socket family.

    Args:
        host: DNS hostname used for address resolution and TLS SNI.
        family: ``4`` for IPv4 or ``6`` for IPv6.
        port: Destination TCP port.
        timeout: Socket timeout in seconds for connect and receive operations.
        path: HTTP path sent in the ``HEAD`` request.

    Returns:
        Structured transport evidence. Resolution failures leave transport
        stages untested and mark the endpoint as failed; later-stage failures
        preserve earlier successful stages.

    Side effects:
        Opens one outbound socket and sends one HTTPS request. No local
        configuration, registry, firewall, or adapter state is changed.

    Limitations:
        The probe reads only a bounded prefix through the first CRLF and
        validates the HTTP status-line shape. It does not prove application
        health, authorization, API semantics, or latency SLO compliance.

    Raises:
        ValueError: If ``family`` is not 4 or 6.
    """
    _validate_family(family)
    af = socket.AF_INET if family == 4 else socket.AF_INET6
    started = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, af, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return TransportEvidence(
            tcp=PathState.NOT_TESTED,
            tls=PathState.NOT_TESTED,
            http=PathState.NOT_TESTED,
            endpoint=PathState.FAIL,
            latency_ms=None,
            address=None,
            limitations=(f"Address resolution failed: {exc}",),
        )

    if not infos:
        return TransportEvidence(
            tcp=PathState.NOT_TESTED,
            tls=PathState.NOT_TESTED,
            http=PathState.NOT_TESTED,
            endpoint=PathState.FAIL,
            latency_ms=None,
            address=None,
            limitations=("No address returned for selected IP family",),
        )

    address: str | None = None
    raw: socket.socket | None = None
    connect_limits: list[str] = []
    for info in infos:
        sockaddr = info[4]
        candidate = str(sockaddr[0])
        try:
            raw = socket.socket(af, socket.SOCK_STREAM)
            raw.settimeout(timeout)
            raw.connect(sockaddr)
            address = candidate
            break
        except OSError as exc:
            connect_limits.append(f"TCP connect failed for {candidate}: {exc}")
            if raw is not None:
                raw.close()
            raw = None
    if raw is None or address is None:
        return TransportEvidence(
            tcp=PathState.FAIL,
            tls=PathState.NOT_TESTED,
            http=PathState.NOT_TESTED,
            endpoint=PathState.FAIL,
            latency_ms=(time.perf_counter() - started) * 1000,
            address=None,
            limitations=tuple(connect_limits),
        )

    context = _tls_client_context()
    try:
        with context.wrap_socket(raw, server_hostname=host) as tls_sock:
            tls = PathState.PASS
            try:
                request = (
                    f"HEAD {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Connection: close\r\n"
                    "User-Agent: wnrt-dual-stack-probe/1\r\n\r\n"
                ).encode("ascii", errors="strict")
                tls_sock.sendall(request)
                response = bytearray()
                while b"\r\n" not in response and len(response) < 256:
                    chunk = tls_sock.recv(min(64, 256 - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
            except (OSError, TimeoutError) as exc:
                return TransportEvidence(
                    tcp=PathState.PASS,
                    tls=tls,
                    http=PathState.FAIL,
                    endpoint=PathState.FAIL,
                    latency_ms=(time.perf_counter() - started) * 1000,
                    address=address,
                    limitations=(f"HTTP request failed: {exc}",),
                )
    except ssl.SSLError as exc:
        return TransportEvidence(
            tcp=PathState.PASS,
            tls=PathState.FAIL,
            http=PathState.NOT_TESTED,
            endpoint=PathState.FAIL,
            latency_ms=(time.perf_counter() - started) * 1000,
            address=address,
            limitations=(f"TLS handshake failed: {exc}",),
        )
    except (OSError, TimeoutError) as exc:
        return TransportEvidence(
            tcp=PathState.PASS,
            tls=PathState.FAIL,
            http=PathState.NOT_TESTED,
            endpoint=PathState.FAIL,
            latency_ms=(time.perf_counter() - started) * 1000,
            address=address,
            limitations=(f"TLS handshake failed: {exc}",),
        )

    elapsed = (time.perf_counter() - started) * 1000
    status_line = bytes(response).split(b"\r\n", 1)[0]
    status_parts = status_line.split()
    http_ok = (
        b"\r\n" in response
        and len(status_parts) >= 2
        and status_parts[0].startswith(b"HTTP/")
        and len(status_parts[1]) == 3
        and status_parts[1].isdigit()
    )
    return TransportEvidence(
        tcp=PathState.PASS,
        tls=tls,
        http=PathState.PASS if http_ok else PathState.FAIL,
        endpoint=PathState.PASS if http_ok else PathState.FAIL,
        latency_ms=elapsed,
        address=address,
        limitations=() if http_ok else ("Endpoint did not return an HTTP status line",),
    )

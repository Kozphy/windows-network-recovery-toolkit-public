"""TCP connectivity probes with normalized Windows/socket error categories.

Module responsibility:
    Attempt TCP connections to one or more loopback addresses on a given port
    and return structured evidence records.  Error codes from the Windows
    socket layer (WSAE* codes) and POSIX errno values are mapped to normalized
    category strings that the classifier understands without OS-specific
    branching.

System placement:
    Called by ``localhost/runner.py`` after name resolution.  Results feed
    ``classify_localhost_failure`` and gate HTTP probing (HTTP is skipped when
    no TCP probe succeeds).

Key invariants:
    * CONNECTION_REFUSED is explicitly annotated as *not* proof of a firewall
      block in the normalized detail string (Windows WSAECONNREFUSED = 10061).
    * Uses stdlib ``socket.create_connection`` only — no third-party networking
      libraries.
    * All errors produce a ``TcpProbeResult`` (never raises); callers can
      rely on the ``connect_success`` flag.

Side effects:
    Establishes real TCP connections to the provided addresses when called
    with live targets.  No filesystem writes; no system state changes.

Failure modes:
    All ``OSError`` and ``TimeoutError`` subclasses are caught and categorized.
    Unknown error codes fall through to ``"UNKNOWN_SOCKET_ERROR"`` rather than
    re-raising.
"""

from __future__ import annotations

import errno
import socket
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

ErrorCategory = str  # CONNECTED | CONNECTION_REFUSED | TIMEOUT | ...


@dataclass(frozen=True)
class TcpProbeResult:
    """Evidence record for a single TCP connect attempt.

    Attributes:
        address: The IP address string that was probed (e.g. ``"127.0.0.1"``,
            ``"::1"``).
        address_family: ``"IPv4"`` or ``"IPv6"`` inferred from *address*.
        port: Target TCP port number.
        connect_success: ``True`` when the three-way handshake completed within
            *timeout*; ``False`` otherwise.
        elapsed_ms: Wall-clock connect time in milliseconds.
        error_category: Normalized category string — ``"CONNECTED"``,
            ``"CONNECTION_REFUSED"``, ``"TIMEOUT"``, ``"NAME_RESOLUTION_FAILED"``,
            ``"NETWORK_UNREACHABLE"``, ``"PERMISSION_ERROR"``, or
            ``"UNKNOWN_SOCKET_ERROR"``.
        windows_error_code: ``winerror`` or ``errno`` integer when available;
            ``None`` on success or for errors without a numeric code.
        detail: Short human-readable error description; for
            ``CONNECTION_REFUSED`` includes the explicit disclaimer that it is
            not proof of a firewall block.
        timestamp_utc: ISO-8601 UTC timestamp at probe start.
    """

    address: str
    address_family: str
    port: int
    connect_success: bool
    elapsed_ms: float
    error_category: ErrorCategory
    windows_error_code: int | None
    detail: str
    timestamp_utc: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "address": self.address,
            "address_family": self.address_family,
            "port": self.port,
            "connect_success": self.connect_success,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "error_category": self.error_category,
            "windows_error_code": self.windows_error_code,
            "detail": self.detail,
            "timestamp_utc": self.timestamp_utc,
        }


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def categorize_socket_error(exc: BaseException) -> tuple[ErrorCategory, int | None, str]:
    """Map an OSError or socket exception to a normalized (category, code, detail) triple.

    Handles Windows WSAE* codes (``winerror`` attribute) and POSIX errno
    values with a priority ordering that avoids overclaiming firewall
    semantics.  Specifically, ``CONNECTION_REFUSED`` detail string makes it
    clear the OS only reports no listener — not a firewall block.

    Args:
        exc: The caught exception; typically ``OSError``, ``TimeoutError``, or
            ``socket.gaierror``.

    Returns:
        ``(category_str, numeric_code_or_None, detail_str)`` tuple.
    """

    if isinstance(exc, TimeoutError):
        return "TIMEOUT", getattr(exc, "winerror", None) or getattr(exc, "errno", None), str(exc)
    if isinstance(exc, socket.gaierror):
        return "NAME_RESOLUTION_FAILED", getattr(exc, "errno", None), str(exc)
    if isinstance(exc, PermissionError):
        return (
            "PERMISSION_ERROR",
            getattr(exc, "winerror", None) or getattr(exc, "errno", None),
            str(exc),
        )
    if isinstance(exc, OSError):
        win = getattr(exc, "winerror", None)
        en = getattr(exc, "errno", None)
        code = win if win is not None else en
        # WSAECONNREFUSED = 10061; ECONNREFUSED
        if code in {10061, errno.ECONNREFUSED} or en == errno.ECONNREFUSED:
            return (
                "CONNECTION_REFUSED",
                code if isinstance(code, int) else None,
                (
                    "Connection refused - typically no listener accepted the connection; "
                    "not by itself proof of a firewall block."
                ),
            )
        if code in {10060, errno.ETIMEDOUT} or en == errno.ETIMEDOUT:
            return "TIMEOUT", code if isinstance(code, int) else None, str(exc)
        if code in {10051, 10065, errno.ENETUNREACH, errno.EHOSTUNREACH}:
            return "NETWORK_UNREACHABLE", code if isinstance(code, int) else None, str(exc)
        if code in {10013, errno.EACCES}:
            return "PERMISSION_ERROR", code if isinstance(code, int) else None, str(exc)
        return "UNKNOWN_SOCKET_ERROR", code if isinstance(code, int) else None, str(exc)
    return "UNKNOWN_SOCKET_ERROR", None, str(exc)


def tcp_probe_address(
    address: str,
    port: int,
    *,
    timeout: float = 2.0,
) -> TcpProbeResult:
    """Probe a single *address*:*port* with a bounded timeout.

    Uses stdlib ``socket.create_connection`` exclusively — no third-party
    networking.  Detects address family from the presence of ``:`` in
    *address* (IPv6 vs IPv4).

    Args:
        address: IP address string to connect to.
        port: TCP port number.
        timeout: Connect timeout in seconds.

    Returns:
        ``TcpProbeResult`` with ``connect_success=True`` on handshake
        completion, or categorized error information otherwise.  Never raises.

    Side effects:
        Establishes and immediately closes a TCP connection on success.
    """

    family = "IPv6" if ":" in address else "IPv4"
    start = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            elapsed = (time.perf_counter() - start) * 1000.0
            return TcpProbeResult(
                address=address,
                address_family=family,
                port=port,
                connect_success=True,
                elapsed_ms=elapsed,
                error_category="CONNECTED",
                windows_error_code=None,
                detail=f"TCP connect to {address}:{port} succeeded",
                timestamp_utc=_now(),
            )
    except (OSError, TimeoutError) as exc:
        elapsed = (time.perf_counter() - start) * 1000.0
        category, code, detail = categorize_socket_error(exc)
        return TcpProbeResult(
            address=address,
            address_family=family,
            port=port,
            connect_success=False,
            elapsed_ms=elapsed,
            error_category=category,
            windows_error_code=code,
            detail=detail,
            timestamp_utc=_now(),
        )


def tcp_probe_many(
    addresses: list[str],
    port: int,
    *,
    timeout: float = 2.0,
) -> list[TcpProbeResult]:
    """Probe each address in *addresses* independently against *port*.

    Probes are executed sequentially in input order; no parallelism.  Input
    order is preserved in the output list so callers can correlate IPv4 and
    IPv6 results by position.

    Args:
        addresses: List of IP address strings from ``loopback_probe_addresses``.
        port: TCP port to probe on every address.
        timeout: Per-address connect timeout in seconds.

    Returns:
        List of ``TcpProbeResult`` with the same length as *addresses*.
    """

    return [tcp_probe_address(addr, port, timeout=timeout) for addr in addresses]

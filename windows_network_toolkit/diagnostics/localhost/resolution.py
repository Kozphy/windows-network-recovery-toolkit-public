"""Name resolution evidence for localhost targets (read-only).

Module responsibility:
    Resolve a localhost-style hostname to its IPv4 and IPv6 addresses via
    ``socket.getaddrinfo`` and optionally scan the hosts file for mentions.
    Provides the address list that drives TCP probing in the diagnose pipeline.

System placement:
    Called by ``localhost/runner.py`` before TCP probing.  ``ResolutionEvidence``
    feeds ``loopback_probe_addresses`` which selects the addresses passed to
    ``tcp_probe_many``.  Never called with live DNS for non-loopback hosts in
    the standard diagnose flow.

Key invariants:
    * Resolution never modifies the hosts file; it is read-only.
    * Addresses are deduplicated and sorted for audit stability.
    * When resolution returns no loopback addresses, ``loopback_probe_addresses``
      falls back to ``["127.0.0.1", "::1"]`` to ensure probing still proceeds.

Side effects:
    Calls ``socket.getaddrinfo`` (network stack lookup — may consult DNS for
    non-loopback names when ``allow_non_loopback=True``).  Reads the system
    hosts file but never writes it.

Failure modes:
    ``socket.gaierror`` or ``OSError`` from ``getaddrinfo`` are appended to
    ``errors`` and ``infos`` is treated as empty.  Hosts-file ``OSError``
    (e.g. permission denied) is silently skipped per candidate path.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ResolutionEvidence:
    """Name-resolution outcome for a localhost diagnostic target.

    Attributes:
        host: The hostname as supplied (e.g. ``"localhost"``, ``"127.0.0.1"``).
        ipv4: Sorted list of resolved IPv4 address strings.
        ipv6: Sorted list of resolved IPv6 address strings (zone IDs stripped).
        has_127_0_0_1: Convenience flag; ``True`` when ``"127.0.0.1"`` is in
            *ipv4*.
        has_ipv6_loopback: Convenience flag; ``True`` when ``"::1"`` is in
            *ipv6*.
        errors: Non-empty when ``getaddrinfo`` raised; propagated to the
            ``LOCALHOST_NAME_RESOLUTION_ERROR`` classification branch.
        hosts_file_mentions: Up to 5 non-comment hosts-file lines that contain
            *host*; aids diagnosis of custom loopback overrides.
        timestamp_utc: ISO-8601 UTC timestamp at resolution time.
    """

    host: str
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    has_127_0_0_1: bool = False
    has_ipv6_loopback: bool = False
    errors: list[str] = field(default_factory=list)
    hosts_file_mentions: list[str] = field(default_factory=list)
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
            "host": self.host,
            "ipv4": list(self.ipv4),
            "ipv6": list(self.ipv6),
            "has_127_0_0_1": self.has_127_0_0_1,
            "has_ipv6_loopback": self.has_ipv6_loopback,
            "errors": list(self.errors),
            "hosts_file_mentions": list(self.hosts_file_mentions),
            "timestamp_utc": self.timestamp_utc,
        }


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_hosts_mentions(host: str) -> list[str]:
    """Best-effort hosts-file lines mentioning *host* (read-only; never edit)."""

    candidates = [
        Path(r"C:\Windows\System32\drivers\etc\hosts"),
        Path("/etc/hosts"),
    ]
    needle = host.lower()
    hits: list[str] = []
    for path in candidates:
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if needle in stripped.lower():
                hits.append(stripped[:200])
                if len(hits) >= 5:
                    return hits
    return hits


def resolve_localhost_host(host: str, *, include_hosts_file: bool = True) -> ResolutionEvidence:
    """Resolve *host* to IPv4/IPv6 addresses via getaddrinfo (no mutation).

    Uses ``socket.SOCK_STREAM`` hint to align with TCP probe semantics.
    IPv6 zone IDs (``%interface``) are stripped from addresses.  Results are
    sorted for deterministic audit output.

    Args:
        host: The hostname or IP literal to resolve.
        include_hosts_file: When ``True``, searches the system hosts file for
            lines mentioning *host* (case-insensitive).

    Returns:
        ``ResolutionEvidence`` with sorted address lists.  ``errors`` is
        non-empty when ``getaddrinfo`` raised.

    Side effects:
        Consults the system resolver (and potentially DNS for non-loopback
        names).  Reads the system hosts file when *include_hosts_file* is True.
    """

    errors: list[str] = []
    ipv4: list[str] = []
    ipv6: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        errors.append(str(exc))
        infos = []
    except OSError as exc:
        errors.append(str(exc))
        infos = []

    for info in infos:
        family, _type, _proto, _canon, sockaddr = info
        addr = sockaddr[0]
        if family == socket.AF_INET and addr not in ipv4:
            ipv4.append(addr)
        elif family == socket.AF_INET6:
            # Strip zone id if present
            bare = addr.split("%", 1)[0]
            if bare not in ipv6:
                ipv6.append(bare)

    # Deterministic sort for audit stability
    ipv4 = sorted(ipv4)
    ipv6 = sorted(ipv6)

    hosts_hits = _safe_hosts_mentions(host) if include_hosts_file else []
    return ResolutionEvidence(
        host=host,
        ipv4=ipv4,
        ipv6=ipv6,
        has_127_0_0_1="127.0.0.1" in ipv4,
        has_ipv6_loopback="::1" in ipv6,
        errors=errors,
        hosts_file_mentions=hosts_hits,
        timestamp_utc=_now(),
    )


def loopback_probe_addresses(resolution: ResolutionEvidence) -> list[str]:
    """Return the ordered address list to use for TCP probing.

    Selects ``127.x.x.x`` addresses from *resolution.ipv4* and ``::1`` from
    *resolution.ipv6*.  Falls back to ``["127.0.0.1", "::1"]`` when the
    resolution returned no usable loopback addresses (e.g. on resolution error
    or when the host is an IP literal not in the loopback range).

    Args:
        resolution: Output of ``resolve_localhost_host``.

    Returns:
        Non-empty list of address strings for ``tcp_probe_many``.
    """

    addrs: list[str] = []
    for a in resolution.ipv4:
        if a.startswith("127.") and a not in addrs:
            addrs.append(a)
    for a in resolution.ipv6:
        if a == "::1" and a not in addrs:
            addrs.append(a)
    if not addrs:
        # Still probe canonical loopbacks when resolution failed or returned empty
        addrs = ["127.0.0.1", "::1"]
    return addrs

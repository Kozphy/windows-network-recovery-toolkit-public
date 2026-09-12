"""Read-only mDNS discovery probe (brief UDP 5353 multicast listen).

Module responsibility:
    Observe mDNS traffic on the local segment and return service/broadcaster hints.

System placement:
    Invoked by ``lan_privacy.collectors.collect_mdns_summary`` and ``mdns-probe`` CLI.

Key invariants:
    * Host-level observation only — no probe packets sent beyond socket bind/listen.
    * Cannot infer malicious intent or exfiltration from mDNS alone.
    * ``inject`` bypasses live socket work for tests and fixtures.

Side effects:
    * Binds UDP port 5353 for a bounded listen window (may fail if port is in use).
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe_mdns(
    *,
    duration_seconds: float = 5.0,
    inject: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Listen for mDNS traffic for a short window (host-level observation only)."""
    if inject is not None:
        return inject

    services: list[dict[str, Any]] = []
    broadcasters: list[dict[str, Any]] = []
    limitations = [
        "mDNS listen is host-level observation on the local segment only.",
        "Cannot confirm device intent or data exfiltration from mDNS alone.",
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(min(max(duration_seconds, 0.5), 60.0))
        try:
            sock.bind(("", MDNS_PORT))
        except OSError:
            return {
                "ok": False,
                "schema_version": "wnt.mdns_probe.v1",
                "timestamp_utc": _now(),
                "services": [],
                "broadcasters": [],
                "packet_count": 0,
                "limitations": limitations
                + ["Could not bind UDP 5353 — port may be in use or access denied."],
            }

        end = datetime.now(UTC).timestamp() + duration_seconds
        packet_count = 0
        seen_sources: set[str] = set()
        while datetime.now(UTC).timestamp() < end:
            try:
                data, addr = sock.recvfrom(4096)
                packet_count += 1
                src_ip = addr[0]
                if src_ip not in seen_sources:
                    seen_sources.add(src_ip)
                    broadcasters.append({"ip": src_ip, "protocol": "MDNS"})
                if b"_services._dns-sd._udp" in data or b".local" in data:
                    snippet = data[:120].decode("utf-8", errors="replace")
                    services.append({"source_ip": src_ip, "snippet": snippet[:80]})
            except socket.timeout:
                break
    finally:
        sock.close()

    return {
        "ok": True,
        "schema_version": "wnt.mdns_probe.v1",
        "timestamp_utc": _now(),
        "services": services[:50],
        "broadcasters": broadcasters[:50],
        "packet_count": packet_count,
        "limitations": limitations,
    }

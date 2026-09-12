"""Read-only SSDP/UPnP discovery probe (M-SEARCH and brief listen).

Module responsibility:
    Send SSDP M-SEARCH and collect UPnP discovery responses on the local segment.

System placement:
    Invoked by ``lan_privacy.collectors.collect_ssdp_summary`` and ``ssdp-probe`` CLI.

Key invariants:
    * Discovery activity is not a security verdict; WAN UPnP needs router evidence.
    * Listen duration is clamped; ``inject`` bypasses live socket work for tests.
    * Returns ``limitations`` on every path for safe downstream wording.

Side effects:
    * Sends one SSDP M-SEARCH multicast and listens on UDP 1900 for a bounded window.
"""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe_ssdp(
    *,
    duration_seconds: float = 5.0,
    inject: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send SSDP M-SEARCH and listen for responses (host-level observation only)."""
    if inject is not None:
        return inject

    services: list[dict[str, Any]] = []
    broadcasters: list[dict[str, Any]] = []
    limitations = [
        "SSDP observation indicates service discovery activity — not malicious intent.",
        "UPnP exposure on WAN requires router-level evidence to assess.",
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(min(max(duration_seconds, 0.5), 60.0))
        try:
            sock.sendto(_MSEARCH, (SSDP_ADDR, SSDP_PORT))
        except OSError as exc:
            return {
                "ok": False,
                "schema_version": "wnt.ssdp_probe.v1",
                "timestamp_utc": _now(),
                "services": [],
                "broadcasters": [],
                "packet_count": 0,
                "limitations": limitations + [f"SSDP send failed: {exc}"],
            }

        end = datetime.now(UTC).timestamp() + duration_seconds
        packet_count = 0
        seen: set[str] = set()
        while datetime.now(UTC).timestamp() < end:
            try:
                data, addr = sock.recvfrom(4096)
                packet_count += 1
                src_ip = addr[0]
                if src_ip not in seen:
                    seen.add(src_ip)
                    broadcasters.append({"ip": src_ip, "protocol": "SSDP"})
                text = data.decode("utf-8", errors="replace")
                st = ""
                for line in text.split("\r\n"):
                    if line.upper().startswith("ST:") or line.upper().startswith("SERVER:"):
                        st = line.strip()
                        break
                services.append({"source_ip": src_ip, "header": st[:120]})
            except socket.timeout:
                break
    finally:
        sock.close()

    return {
        "ok": True,
        "schema_version": "wnt.ssdp_probe.v1",
        "timestamp_utc": _now(),
        "services": services[:50],
        "broadcasters": broadcasters[:50],
        "packet_count": packet_count,
        "limitations": limitations,
    }

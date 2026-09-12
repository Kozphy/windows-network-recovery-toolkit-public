"""Router evidence models — canonical event types and serialization.

Module responsibility:
    Define ``RouterEvent`` dataclass, ``RouterEventType`` enum, and ``ROUTER_SCHEMA``
    for normalized router log rows.

System placement:
    Shared by ``importers``, ``normalizer``, ``correlator``, and ``runner``.

Key invariants:
    * ``evidence_source`` defaults to ``ROUTER_LEVEL_EVIDENCE`` on all events.
    * DNS events expose ``domain`` via ``query`` fallback in ``to_dict``.
    * Schema version ``wnt.router_evidence.v1`` tags serialized JSONL.

Side effects:
    * None — types and serialization helpers only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

ROUTER_SCHEMA = "wnt.router_evidence.v1"


class RouterEventType(StrEnum):
    """Supported router log event categories for import and correlation."""

    DNS = "dns"
    FIREWALL = "firewall"
    DHCP = "dhcp"
    DEVICE = "device"


@dataclass
class RouterEvent:
    """Normalized representation of a single router log entry.

    Attributes:
        event_id: Stable SHA-256-derived identifier built from key fields.
        timestamp_utc: ISO-8601 UTC timestamp (best-effort from log source).
        event_type: One of ``RouterEventType`` values.
        evidence_source: Always ``"ROUTER_LEVEL_EVIDENCE"`` for router-imported rows.
        client_ip: Client IPv4 address for DNS/DHCP events.
        mac: Client MAC address for DHCP/device events.
        domain: Resolved domain name for DNS events (falls back to ``query``).
        query: Raw DNS query string.
        src_ip: Source IP for firewall events.
        dst_ip: Destination IP for firewall events.
        port: Destination port for firewall events (0 when absent).
        action: Firewall action string (e.g. ``"ALLOW"``, ``"DENY"``).
        hostname: Client hostname from DHCP or device-list rows.
        raw: Original parsed log row dict retained for provenance.
    """

    event_id: str
    timestamp_utc: str
    event_type: str
    evidence_source: str = "ROUTER_LEVEL_EVIDENCE"
    client_ip: str = ""
    mac: str = ""
    domain: str = ""
    query: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    port: int = 0
    action: str = ""
    hostname: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict; DNS events normalize ``domain`` from ``query``.

        Returns:
            Dict representation of this event with ``schema_version`` and
            ``evidence_source`` suitable for JSONL serialization.
        """
        d = asdict(self)
        if self.event_type == RouterEventType.DNS.value:
            d["domain"] = self.domain or self.query
        return d

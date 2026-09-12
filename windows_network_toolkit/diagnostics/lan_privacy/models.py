"""LAN privacy data models — devices, observations, classifications, limitations.

Module responsibility:
    Define schema version, evidence tiers, classification enums, and dataclass
    payloads shared across collectors, classifier, scoring, and reports.

System placement:
    Imported throughout ``windows_network_toolkit.diagnostics.lan_privacy`` and tests.

Key invariants:
    * ``LAN_LIMITATIONS`` must accompany user-facing outputs — not security verdicts.
    * ``EvidenceSource`` distinguishes host, router, and packet-capture tiers.
    * ``SCHEMA_VERSION`` tags all serialized LAN privacy artifacts.

Side effects:
    * None — types and constants only.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "wnt.lan_privacy.v1"

LAN_LIMITATIONS = [
    "Host-level observation is not proof of malicious intent.",
    "Scanning activity is not confirmed compromise without router or packet-capture evidence.",
    "Cannot confirm data exfiltration from Windows host telemetry alone.",
    "Attribution requires additional evidence beyond discovery protocol broadcasts.",
]


class EvidenceSource(StrEnum):
    """LAN evidence provenance tiers.

    Variants:
        HOST_LEVEL_OBSERVATION: Evidence collected from the endpoint host.
        ROUTER_LEVEL_EVIDENCE: Router log or DHCP evidence.
        PACKET_CAPTURE_EVIDENCE: Packet-capture backed evidence.
        INSUFFICIENT_EVIDENCE: Placeholder when source evidence is missing.

    Side effects:
        None."""
    HOST_LEVEL_OBSERVATION = "HOST_LEVEL_OBSERVATION"
    ROUTER_LEVEL_EVIDENCE = "ROUTER_LEVEL_EVIDENCE"
    PACKET_CAPTURE_EVIDENCE = "PACKET_CAPTURE_EVIDENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class LanClassification(StrEnum):
    """LAN privacy classification labels for management triage.

    Variants:
        NORMAL_DISCOVERY: Expected local discovery activity.
        NEW_DEVICE_OBSERVED: A device not in the baseline was observed.
        FREQUENT_DISCOVERY: Discovery traffic volume is elevated.
        BROAD_SUBNET_PROBING: Broad subnet probing pattern observed.
        POSSIBLE_LATERAL_RECON: Pattern suggests lateral reconnaissance for review.
        UNKNOWN_IOT_DEVICE: Device has IoT-like or unknown-vendor indicators.
        INSUFFICIENT_EVIDENCE: Evidence is not enough to classify behavior.

    Side effects:
        None.

    Audit Notes:
        These labels are observational triage signals, not accusations or proof of compromise."""
    NORMAL_DISCOVERY = "NORMAL_DISCOVERY"
    NEW_DEVICE_OBSERVED = "NEW_DEVICE_OBSERVED"
    FREQUENT_DISCOVERY = "FREQUENT_DISCOVERY"
    BROAD_SUBNET_PROBING = "BROAD_SUBNET_PROBING"
    POSSIBLE_LATERAL_RECON = "POSSIBLE_LATERAL_RECON"
    UNKNOWN_IOT_DEVICE = "UNKNOWN_IOT_DEVICE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class LanProtocol(StrEnum):
    """LAN protocol labels normalized by collectors.

    Variants:
        MDNS: Multicast DNS observation.
        SSDP: Simple Service Discovery Protocol observation.
        UPNP: UPnP-related observation.
        NETBIOS: NetBIOS discovery observation.
        ARP: ARP/neighbor observation.
        ICMP: ICMP observation.
        TCP_SYN: TCP SYN/probe observation.

    Side effects:
        None."""
    MDNS = "MDNS"
    SSDP = "SSDP"
    UPNP = "UPNP"
    NETBIOS = "NETBIOS"
    ARP = "ARP"
    ICMP = "ICMP"
    TCP_SYN = "TCP_SYN"


@dataclass
class LanDevice:
    """A single device observed on the local network.

    Attributes:
        ip: IPv4 address observed in the ARP/neighbor table.
        mac: MAC address (upper-case colon-separated) or empty string.
        hostname: Reverse-DNS hostname, or empty string if not resolved.
        vendor: OUI vendor name from the embedded lookup table.
        vendor_known: ``False`` when the OUI prefix is not in the table.
        first_seen_utc: ISO-8601 UTC timestamp of first observation.
        last_seen_utc: ISO-8601 UTC timestamp of most recent observation.
        flags: Annotation tags (e.g. ``"unknown_vendor"``, ``"iot_like"``).
    """

    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    vendor_known: bool = True
    first_seen_utc: str = ""
    last_seen_utc: str = ""
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON serialization."""
        return asdict(self)


@dataclass
class LanObservation:
    """A single normalized LAN protocol observation event.

    Attributes:
        event_id: Stable SHA-256-derived identifier for deduplication.
        timestamp_utc: ISO-8601 UTC timestamp of the observation.
        protocol: LAN protocol (one of ``LanProtocol`` values, e.g. ``"ARP"``).
        source_ip: Originating IP address, or empty string.
        source_mac: Originating MAC address, or empty string.
        target_ip: Target IP address probed or discovered, or empty string.
        target_port: Target port number (0 when not applicable).
        direction: Traffic directionality hint (e.g. ``"broadcast"``, ``"unicast"``).
        evidence_source: Provenance tier from ``EvidenceSource``.
        raw: Original observation dict for provenance; may be empty.
    """

    event_id: str
    timestamp_utc: str
    protocol: str
    source_ip: str = ""
    source_mac: str = ""
    target_ip: str = ""
    target_port: int = 0
    direction: str = "broadcast"
    evidence_source: str = EvidenceSource.HOST_LEVEL_OBSERVATION.value
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON serialization."""
        return asdict(self)


@dataclass
class ClassificationResult:
    """Output of ``classifier.classify_lan_behavior``.

    Attributes:
        primary_classification: Primary ``LanClassification`` label string.
        secondary_signals: Additional observational signals supporting the label.
        confidence: Ordinal heuristic in [0.0, 1.0].
        reasoning: Human-readable explanation of how the label was chosen.
        limitations: Copied from ``LAN_LIMITATIONS`` plus any classification-specific caveats.
        highest_evidence_source: Best ``EvidenceSource`` present in the input.
    """

    primary_classification: str
    secondary_signals: list[str] = field(default_factory=list)
    confidence: float = 0.5
    reasoning: str = ""
    limitations: list[str] = field(default_factory=list)
    highest_evidence_source: str = EvidenceSource.HOST_LEVEL_OBSERVATION.value

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON serialization."""
        return asdict(self)

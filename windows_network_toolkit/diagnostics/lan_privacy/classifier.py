"""LAN behavior classifier — evidence-based labels only.

Module responsibility:
    Derive ``LanClassification`` labels from observation counts, probe breadth, and
    vendor context using tunable thresholds.

System placement:
    Used by ``lan_privacy.runner`` report/risk pipelines and ``lan-classify`` CLI.

Key invariants:
    * Never emits malware or exfiltration verdicts — classifications are observational.
    * Insufficient observation volume maps to ``INSUFFICIENT_EVIDENCE``.
    * Output always carries ``LAN_LIMITATIONS`` for downstream report guardrails.

Side effects:
    * None — pure aggregation over in-memory observation lists.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .models import (
    LAN_LIMITATIONS,
    ClassificationResult,
    EvidenceSource,
    LanClassification,
)

# Tunable thresholds
MIN_EVENTS = 3
FREQUENT_DISCOVERY_RATE = 8
BROAD_PROBE_TARGETS = 5
LATERAL_PROBE_TARGETS = 8
RECURRENCE_SESSIONS = 2

CASTING_VENDORS = frozenset({"roku", "samsung", "google", "amazon", "apple"})


def _device_vendor_map(devices: list[dict[str, Any]]) -> dict[str, str]:
    return {d.get("ip", ""): (d.get("vendor") or "").lower() for d in devices}


def _probe_stats(observations: list[dict[str, Any]]) -> dict[str, Any]:
    by_source: Counter[str] = Counter()
    targets_by_source: dict[str, set[str]] = defaultdict(set)
    protocols: Counter[str] = Counter()
    sessions: Counter[str] = Counter()

    for obs in observations:
        src = obs.get("source_ip") or obs.get("source_mac") or "unknown"
        tgt = obs.get("target_ip") or ""
        proto = obs.get("protocol", "")
        by_source[src] += 1
        protocols[proto] += 1
        if tgt:
            targets_by_source[src].add(tgt)
        hour = (obs.get("timestamp_utc") or "")[:13]
        if hour:
            sessions[f"{src}:{hour}"] += 1

    max_breadth = max((len(v) for v in targets_by_source.values()), default=0)
    max_freq = max(by_source.values(), default=0)
    recurrence = sum(1 for c in sessions.values() if c >= 2)

    return {
        "by_source": dict(by_source),
        "targets_by_source": {k: list(v) for k, v in targets_by_source.items()},
        "protocols": dict(protocols),
        "max_breadth": max_breadth,
        "max_freq": max_freq,
        "recurrence": recurrence,
        "event_count": len(observations),
    }


def _highest_evidence_source(observations: list[dict[str, Any]]) -> str:
    sources = {
        o.get("evidence_source", EvidenceSource.HOST_LEVEL_OBSERVATION.value) for o in observations
    }
    if EvidenceSource.ROUTER_LEVEL_EVIDENCE.value in sources:
        return EvidenceSource.ROUTER_LEVEL_EVIDENCE.value
    if EvidenceSource.PACKET_CAPTURE_EVIDENCE.value in sources:
        return EvidenceSource.PACKET_CAPTURE_EVIDENCE.value
    if not observations or len(observations) < MIN_EVENTS:
        return EvidenceSource.INSUFFICIENT_EVIDENCE.value
    return EvidenceSource.HOST_LEVEL_OBSERVATION.value


def classify_lan_behavior(
    *,
    observations: list[dict[str, Any]],
    devices: list[dict[str, Any]] | None = None,
    baseline_device_ips: set[str] | None = None,
) -> ClassificationResult:
    """Classify LAN discovery and probing patterns from observation evidence.

    Applies ordered thresholds to determine the most significant behavioral
    label, from reconnaissance-like patterns down to normal discovery noise.
    All labels are observational — not malware verdicts or security findings.

    Args:
        observations: List of ``LanObservation``-compatible dicts collected by
            ``collectors.collect_all`` or ``watch.run_lan_watch``.
        devices: Optional device inventory list (``LanDevice``-compatible dicts)
            used for vendor context and unknown-device flagging.
        baseline_device_ips: Optional set of previously known IP addresses;
            new IPs trigger the ``NEW_DEVICE_OBSERVED`` secondary signal.

    Returns:
        A ``ClassificationResult`` with ``primary_classification``,
        ``secondary_signals``, ``confidence``, ``reasoning``,
        ``limitations``, and ``highest_evidence_source``.
    """
    devices = devices or []
    stats = _probe_stats(observations)
    evidence_src = _highest_evidence_source(observations)
    limitations = list(LAN_LIMITATIONS)
    secondary: list[str] = []
    vendor_map = _device_vendor_map(devices)

    if stats["event_count"] < MIN_EVENTS:
        return ClassificationResult(
            primary_classification=LanClassification.INSUFFICIENT_EVIDENCE.value,
            secondary_signals=["low_event_count"],
            confidence=0.3,
            reasoning="Insufficient observation volume for confident LAN behavior classification.",
            limitations=limitations
            + ["Requires additional evidence — extend lan-watch or import router logs."],
            highest_evidence_source=EvidenceSource.INSUFFICIENT_EVIDENCE.value,
        )

    # New device check
    current_ips = {d.get("ip") for d in devices if d.get("ip")}
    if baseline_device_ips and current_ips - baseline_device_ips:
        secondary.append("new_device_in_inventory")

    # Unknown IoT
    unknown_iot = any(
        "unknown_vendor" in (d.get("flags") or []) and "iot_like" not in (d.get("flags") or [])
        for d in devices
    )
    active_unknown = any(
        src in {d.get("ip") for d in devices if "unknown_vendor" in (d.get("flags") or [])}
        for src in stats["by_source"]
    )

    # Broad / lateral probing
    icmp_syn = stats["protocols"].get("ICMP", 0) + stats["protocols"].get("TCP_SYN", 0)
    if stats["max_breadth"] >= LATERAL_PROBE_TARGETS and icmp_syn >= 3:
        return ClassificationResult(
            primary_classification=LanClassification.POSSIBLE_LATERAL_RECON.value,
            secondary_signals=["multi_target_probe", "icmp_or_syn"],
            confidence=0.65,
            reasoning=(
                "Observed possible reconnaissance pattern — repeated probes across multiple "
                "local targets. Requires router-level or packet-capture evidence for attribution."
            ),
            limitations=limitations,
            highest_evidence_source=evidence_src,
        )

    if stats["max_breadth"] >= BROAD_PROBE_TARGETS:
        return ClassificationResult(
            primary_classification=LanClassification.BROAD_SUBNET_PROBING.value,
            secondary_signals=["broad_target_set"],
            confidence=0.6,
            reasoning="Observed probing activity across multiple local addresses on the subnet.",
            limitations=limitations,
            highest_evidence_source=evidence_src,
        )

    if active_unknown or (unknown_iot and stats["max_freq"] >= 3):
        return ClassificationResult(
            primary_classification=LanClassification.UNKNOWN_IOT_DEVICE.value,
            secondary_signals=["unknown_vendor", "discovery_active"],
            confidence=0.55,
            reasoning=(
                "Unknown-vendor device observed with local network discovery activity. "
                "Consistent with unmanaged IoT — requires additional evidence for intent."
            ),
            limitations=limitations,
            highest_evidence_source=evidence_src,
        )

    if stats["max_freq"] >= FREQUENT_DISCOVERY_RATE:
        # Check if casting vendor (benign frequent discovery)
        top_src = max(stats["by_source"], key=stats["by_source"].get) if stats["by_source"] else ""
        vendor = vendor_map.get(top_src, "")
        if any(cv in vendor for cv in CASTING_VENDORS) and stats["max_breadth"] <= 2:
            return ClassificationResult(
                primary_classification=LanClassification.FREQUENT_DISCOVERY.value,
                secondary_signals=["casting_vendor", "high_broadcast_rate"],
                confidence=0.5,
                reasoning=(
                    "Frequent service discovery observed from a known casting/TV vendor — "
                    "consistent with normal smart TV or casting device behavior."
                ),
                limitations=limitations,
                highest_evidence_source=evidence_src,
            )
        return ClassificationResult(
            primary_classification=LanClassification.FREQUENT_DISCOVERY.value,
            secondary_signals=["high_discovery_rate"],
            confidence=0.55,
            reasoning="Frequent local network discovery broadcasts observed.",
            limitations=limitations,
            highest_evidence_source=evidence_src,
        )

    if secondary and "new_device_in_inventory" in secondary:
        return ClassificationResult(
            primary_classification=LanClassification.NEW_DEVICE_OBSERVED.value,
            secondary_signals=secondary,
            confidence=0.45,
            reasoning="New device observed on local network inventory.",
            limitations=limitations,
            highest_evidence_source=evidence_src,
        )

    return ClassificationResult(
        primary_classification=LanClassification.NORMAL_DISCOVERY.value,
        secondary_signals=["low_risk_discovery"],
        confidence=0.4,
        reasoning="Observed local network discovery activity within normal home/SOHO patterns.",
        limitations=limitations,
        highest_evidence_source=evidence_src,
    )

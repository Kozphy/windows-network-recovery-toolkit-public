"""Correlate host LAN observations with router evidence.

Module responsibility:
    Join router DNS/DHCP/device events to host inventory by IP/MAC and summarize
    matched vs unmatched DNS and enrichment gaps.

System placement:
    Used by ``router_evidence.runner.run_router_correlation`` and ``lan_privacy.runner``
    when router JSONL is available.

Key invariants:
    * Correlation links identifiers only — does not prove malicious intent.
    * Unmatched DNS retained for visibility when inventory lacks the client IP.
    * Output suitable for executive report external-domain sections.

Side effects:
    * None — pure join over in-memory event lists.
"""

from __future__ import annotations

from typing import Any


def correlate_host_router(
    host_observations: list[dict[str, Any]],
    router_events: list[dict[str, Any]],
    devices: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Join router DNS/DHCP/device events with host inventory by IP and MAC.

    Partitions router events into matched DNS (client IP/MAC found in inventory),
    unmatched DNS (client not in inventory — may be a device absent from ARP cache),
    and DHCP-enriched devices (seen in router DHCP but not in host ARP cache).

    Args:
        host_observations: Flat list of ``LanObservation`` dicts from lan-watch.
        router_events: Normalized router event dicts from ``load_router_jsonl``.
        devices: Optional device inventory list (``LanDevice.to_dict()`` entries)
            used to build IP-to-device and MAC-to-device index maps.

    Returns:
        Dict with:
            ``ok`` (bool): Always ``True`` when correlation completes.
            ``matched_dns`` (list): DNS events whose client is in inventory.
            ``unmatched_dns`` (list): DNS events with unknown client.
            ``dhcp_enriched`` (list): Devices seen in router but not in host cache.
            ``highest_evidence_source`` (str): ``"ROUTER_LEVEL_EVIDENCE"`` when
                router events were present; otherwise ``"HOST_LEVEL_OBSERVATION"``.
            ``limitations`` (list[str]): Epistemic caveats on correlation.
    """
    devices = devices or []
    ip_to_device = {d.get("ip"): d for d in devices if d.get("ip")}
    mac_to_device = {d.get("mac", "").upper(): d for d in devices if d.get("mac")}

    matched_dns: list[dict[str, Any]] = []
    unmatched_dns: list[dict[str, Any]] = []
    dhcp_enriched: list[dict[str, Any]] = []

    for ev in router_events:
        etype = ev.get("event_type", "")
        client = ev.get("client_ip") or ev.get("src_ip") or ""
        mac = (ev.get("mac") or "").upper()

        if etype == "dns":
            device = ip_to_device.get(client) or mac_to_device.get(mac)
            entry = {
                "client_ip": client,
                "domain": ev.get("domain") or ev.get("query", ""),
                "device_vendor": (device or {}).get("vendor", ""),
                "evidence_source": "ROUTER_LEVEL_EVIDENCE",
            }
            if device:
                matched_dns.append(entry)
            else:
                unmatched_dns.append(entry)
        elif etype in {"dhcp", "device"}:
            ip = ev.get("client_ip") or ""
            if ip and ip not in ip_to_device:
                dhcp_enriched.append(
                    {
                        "ip": ip,
                        "mac": ev.get("mac", ""),
                        "hostname": ev.get("hostname", ""),
                        "note": "device_in_router_not_in_host_cache",
                    }
                )

    highest = "HOST_LEVEL_OBSERVATION"
    if router_events:
        highest = "ROUTER_LEVEL_EVIDENCE"

    return {
        "ok": True,
        "matched_dns": matched_dns,
        "unmatched_dns": unmatched_dns,
        "dhcp_enriched": dhcp_enriched,
        "highest_evidence_source": highest,
        "limitations": [
            "Correlation links IP/MAC — does not prove device intent or data exfiltration.",
            "Unmatched DNS may indicate devices not in host ARP cache.",
        ],
    }

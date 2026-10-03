"""Analytics pipeline evidence schema — normalized events with raw snapshots preserved.

Module responsibility:
    Define ``EvidenceEvent`` and normalizers that convert proxy CLI/audit rows into a stable
    analytics shape while preserving ``raw_snapshot`` for replay.

System placement:
    Upstream of ``incident_classifier`` and ``analytics_pipeline``. Tiers T0–T7 label claim
    strength — they do not upgrade proof automatically and never grant execution authority.

Key invariants:
    * ``event_id`` is deterministic from timestamp, type, and stable fields.
    * ``timestamp_utc`` expected as ISO-8601 UTC string.
    * ``STANDARD_LIMITATIONS`` appended to normalized events where applicable.

Data handling:
    Missing optional fields become empty dicts or false — normalizers do not invent probe results.
    Duplicate event_ids deduplicated in ``analytics_pipeline._dedupe_events``.
"""

from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class EvidenceTier(StrEnum):
    """Evidence strength labels used by analytics events.

    Variants:
        T0_OBSERVATION: Raw observation with no corroboration.
        T1_STATE_EVIDENCE: Local configuration or state evidence.
        T2_RUNTIME_EVIDENCE: Runtime listener/process evidence.
        T3_PATH_EVIDENCE: Network-path probe evidence.
        T4_WRITER_PROOF: Registry writer proof from telemetry.
        T5_GOVERNANCE_PROOF: Governance or policy proof.
        T6_CONTROLLED_VALIDATION: Controlled validation evidence.
        T7_INDEPENDENT_VERIFICATION: Independent verification evidence.

    Side effects:
        None.

    Audit Notes:
        Evidence tier describes claim strength only; it does not authorize remediation."""

    T0_OBSERVATION = "T0_OBSERVATION"
    T1_STATE_EVIDENCE = "T1_STATE_EVIDENCE"
    T2_RUNTIME_EVIDENCE = "T2_RUNTIME_EVIDENCE"
    T3_PATH_EVIDENCE = "T3_PATH_EVIDENCE"
    T4_WRITER_PROOF = "T4_WRITER_PROOF"
    T5_GOVERNANCE_PROOF = "T5_GOVERNANCE_PROOF"
    T6_CONTROLLED_VALIDATION = "T6_CONTROLLED_VALIDATION"
    T7_INDEPENDENT_VERIFICATION = "T7_INDEPENDENT_VERIFICATION"


STANDARD_LIMITATIONS = [
    "Listener ownership is correlation, not registry writer proof.",
    "Registry writer attribution requires Sysmon, Procmon, ETW, or EventLog evidence.",
    "Successful proxy probe does not prove the proxy is safe or intended.",
    "Risk classification is a triage signal, not a malware verdict.",
    "Evidence tier does not grant execution authority; policy and human approval remain separate.",
]


@dataclass
class EvidenceEvent:
    """Normalized evidence row for analytics pipeline and export.

    T0–T5 cover observation through governance evidence. T6 represents
    controlled validation and T7 independent verification. Normalizers below
    remain conservative and emit only tiers directly supported by their input;
    T6/T7 are awarded by the governance proof resolver from complete bundles.
    """

    event_id: str
    timestamp_utc: str
    endpoint_id: str | None
    evidence_type: str
    source_command: str
    raw_snapshot: dict[str, Any]
    normalized_fields: dict[str, Any]
    evidence_tier: str
    evidence_summary: str
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return asdict(self)


def make_event_id(timestamp_utc: str, evidence_type: str, stable_fields: dict[str, Any]) -> str:
    """Deterministic event id from stable fields (sorted JSON hash)."""
    payload = json.dumps(
        {"timestamp_utc": timestamp_utc, "evidence_type": evidence_type, "stable": stable_fields},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def default_endpoint_id() -> str:
    """Return the local endpoint identifier used when evidence omits one.

    Args:
        None.

    Returns:
        Hostname from ``socket.gethostname()``, or ``"local-endpoint"`` if unavailable.

    Side effects:
        Reads the local hostname through the socket library."""
    try:
        return socket.gethostname()
    except OSError:
        return "local-endpoint"


def normalize_proxy_state(
    raw: dict[str, Any], *, source_command: str = "proxy-status"
) -> EvidenceEvent:
    """Normalize a raw proxy state snapshot into an evidence event.

    Args:
        raw: Proxy state dict from CLI output, fixture data, or audit row.
        source_command: Command name recorded as event provenance.

    Returns:
        ``EvidenceEvent`` with normalized WinINET/WinHTTP fields and T1 state evidence.

    Side effects:
        May read the local hostname when ``endpoint_id`` is absent.

    Audit Notes:
        Normalization preserves the raw snapshot and appends standard limitations; it does not infer writer identity."""
    ts = str(raw.get("timestamp_utc") or raw.get("timestamp") or "")
    endpoint_id = raw.get("endpoint_id") or default_endpoint_id()
    enabled = bool(raw.get("wininet_proxy_enabled") or raw.get("proxy_enable"))
    server = str(raw.get("wininet_proxy_server") or raw.get("proxy_server") or "")
    winhttp_direct = raw.get("winhttp_direct_access")
    normalized = {
        "wininet_proxy_enabled": enabled,
        "wininet_proxy_server": server,
        "wininet_auto_config_url": str(
            raw.get("wininet_auto_config_url") or raw.get("auto_config_url") or ""
        ),
        "winhttp_direct_access": winhttp_direct,
        "localhost_port": raw.get("localhost_port"),
        "wininet_winhttp_mismatch": bool(enabled and winhttp_direct),
    }
    stable = {"server": server, "enabled": enabled, "winhttp_direct": winhttp_direct}
    return EvidenceEvent(
        event_id=make_event_id(ts, "proxy_state", stable),
        timestamp_utc=ts,
        endpoint_id=str(endpoint_id) if endpoint_id else None,
        evidence_type="proxy_state",
        source_command=source_command,
        raw_snapshot=dict(raw),
        normalized_fields=normalized,
        evidence_tier=EvidenceTier.T1_STATE_EVIDENCE.value,
        evidence_summary=f"WinINET proxy_enable={int(enabled)} proxy_server={server or '(none)'}",
        limitations=list(STANDARD_LIMITATIONS),
    )


def normalize_listener_state(
    raw: dict[str, Any], *, source_command: str = "proxy-owner"
) -> EvidenceEvent:
    """Normalize localhost listener attribution into an evidence event.

    Args:
        raw: Listener owner dict, optionally including process metadata or writer proof.
        source_command: Command name recorded as event provenance.

    Returns:
        ``EvidenceEvent`` with listener fields and T2 runtime evidence, or T4 writer proof when supported by input.

    Side effects:
        May read the local hostname when ``endpoint_id`` is absent.

    Audit Notes:
        Listener ownership is correlation unless writer proof fields are present."""
    ts = str(raw.get("timestamp_utc") or raw.get("timestamp") or "")
    endpoint_id = raw.get("endpoint_id") or default_endpoint_id()
    proc = raw.get("process") if isinstance(raw.get("process"), dict) else {}
    port = raw.get("localhost_port")
    normalized = {
        "listener_found": bool(raw.get("listener_found")),
        "localhost_port": port,
        "listener_pid": proc.get("pid"),
        "listener_name": proc.get("name"),
        "listener_path": proc.get("exe_path"),
        "listener_command_line": proc.get("cmdline"),
    }
    stable = {"port": port, "pid": proc.get("pid"), "name": proc.get("name")}
    tier = EvidenceTier.T2_RUNTIME_EVIDENCE.value
    if raw.get("writer_proof") or raw.get("sysmon_event_id") == 13:
        tier = EvidenceTier.T4_WRITER_PROOF.value
    summary = f"listener_found={normalized['listener_found']} port={port} process={proc.get('name') or 'unknown'}"
    return EvidenceEvent(
        event_id=make_event_id(ts, "listener_state", stable),
        timestamp_utc=ts,
        endpoint_id=str(endpoint_id) if endpoint_id else None,
        evidence_type="listener_state",
        source_command=source_command,
        raw_snapshot=dict(raw),
        normalized_fields=normalized,
        evidence_tier=tier,
        evidence_summary=summary,
        limitations=list(STANDARD_LIMITATIONS),
    )


def normalize_probe_result(
    raw: dict[str, Any], *, source_command: str = "proxy-health"
) -> EvidenceEvent:
    """Normalize proxy-health path probe output into an evidence event.

    Args:
        raw: Proxy-health payload or nested ``health`` dict.
        source_command: Command name recorded as event provenance.

    Returns:
        ``EvidenceEvent`` with proxy/direct path outcomes and T3 path evidence.

    Side effects:
        May read the local hostname when ``endpoint_id`` is absent.

    Audit Notes:
        Path success or failure supports reliability triage; it does not prove listener intent or safety."""
    ts = str(raw.get("timestamp_utc") or raw.get("timestamp") or "")
    endpoint_id = raw.get("endpoint_id") or default_endpoint_id()
    health = raw.get("health") if isinstance(raw.get("health"), dict) else raw
    proxy_probe_ok = health.get("proxy_probe_ok")
    if proxy_probe_ok is None:
        proxy_probe_ok = health.get("external_probe_ok")
    normalized = {
        "proxy_status": health.get("proxy_status"),
        "tcp_listening": health.get("tcp_listening"),
        "tcp_connect_ok": health.get("tcp_connect_ok"),
        "direct_probe_ok": health.get("direct_probe_ok"),
        # False is a measured failure, not a missing value. Avoid ``a or b`` here
        # because it silently converted False into None when no fallback existed.
        "proxy_probe_ok": proxy_probe_ok,
        "proxy_https_connect_ok": health.get("proxy_https_connect_ok"),
        "failure_reason": health.get("failure_reason"),
    }
    stable = {
        "proxy_status": normalized["proxy_status"],
        "direct": normalized["direct_probe_ok"],
        "proxy": normalized["proxy_probe_ok"],
    }
    return EvidenceEvent(
        event_id=make_event_id(ts, "probe_result", stable),
        timestamp_utc=ts,
        endpoint_id=str(endpoint_id) if endpoint_id else None,
        evidence_type="probe_result",
        source_command=source_command,
        raw_snapshot=dict(raw),
        normalized_fields=normalized,
        evidence_tier=EvidenceTier.T3_PATH_EVIDENCE.value,
        evidence_summary=f"proxy_status={normalized.get('proxy_status')} direct={normalized.get('direct_probe_ok')} proxy={normalized.get('proxy_probe_ok')}",
        limitations=list(STANDARD_LIMITATIONS),
    )


def normalize_proxy_change_event(
    raw: dict[str, Any], *, source_command: str = "proxy-watch"
) -> EvidenceEvent:
    """Normalize a proxy-watch before/after change into an evidence event.

    Args:
        raw: Change row containing ``old_state``/``new_state`` or ``before``/``after``.
        source_command: Command name recorded as event provenance.

    Returns:
        ``EvidenceEvent`` describing the observed ProxyServer transition with T1 state evidence.

    Side effects:
        May read the local hostname when ``endpoint_id`` is absent.

    Audit Notes:
        Reverter fields are copied as observations; writer attribution requires separate telemetry."""
    ts = str(raw.get("timestamp_utc") or raw.get("timestamp") or "")
    endpoint_id = raw.get("endpoint_id") or default_endpoint_id()
    old_state = raw.get("old_state") or raw.get("before") or {}
    new_state = raw.get("new_state") or raw.get("after") or {}
    normalized = {
        "old_proxy_server": old_state.get("wininet_proxy_server"),
        "new_proxy_server": new_state.get("wininet_proxy_server"),
        "old_proxy_enabled": old_state.get("wininet_proxy_enabled"),
        "new_proxy_enabled": new_state.get("wininet_proxy_enabled"),
        "localhost_port": new_state.get("localhost_port"),
        "reverter_suspected": bool(raw.get("reverter_suspected")),
        "reverter_status": (raw.get("reverter_diagnosis") or {}).get("status"),
    }
    stable = {
        "old": normalized["old_proxy_server"],
        "new": normalized["new_proxy_server"],
        "enabled": normalized["new_proxy_enabled"],
    }
    return EvidenceEvent(
        event_id=make_event_id(ts, "proxy_change", stable),
        timestamp_utc=ts,
        endpoint_id=str(endpoint_id) if endpoint_id else None,
        evidence_type="proxy_change",
        source_command=source_command,
        raw_snapshot=dict(raw),
        normalized_fields=normalized,
        evidence_tier=EvidenceTier.T1_STATE_EVIDENCE.value,
        evidence_summary=f"ProxyServer {normalized['old_proxy_server']} -> {normalized['new_proxy_server']}",
        limitations=list(STANDARD_LIMITATIONS),
    )


def events_to_json(events: list[EvidenceEvent]) -> list[dict[str, Any]]:
    """Serialize evidence events to JSON-compatible dictionaries.

    Args:
        events: Evidence events to serialize.

    Returns:
        List of dictionaries from ``EvidenceEvent.to_dict()``.

    Side effects:
        None."""
    return [e.to_dict() for e in events]


def events_from_dicts(rows: list[dict[str, Any]]) -> list[EvidenceEvent]:
    """Hydrate evidence events from dictionaries.

    Args:
        rows: Dictionaries containing ``EvidenceEvent`` field names.

    Returns:
        List of ``EvidenceEvent`` objects; unknown keys are ignored.

    Side effects:
        None."""
    out: list[EvidenceEvent] = []
    for row in rows:
        out.append(
            EvidenceEvent(
                **{k: v for k, v in row.items() if k in EvidenceEvent.__dataclass_fields__}
            )
        )
    return out

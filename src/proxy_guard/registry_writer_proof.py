"""Registry writer proof engine — Sysmon Event ID 13 and fixture-backed evidence.

Upgrades correlation to **proven registry writer** only when Event ID 13 directly matches
monitored WinINET proxy values under Internet Settings.

Audit Notes:
    Absence of Sysmon rows does not prove innocence — only that write proof is unavailable.
"""

from __future__ import annotations

import json
import platform
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from src.telemetry.registry_targets import (
    is_proxy_registry_target,
    proxy_registry_value_name,
)
from src.telemetry.sysmon_reader import (
    SysmonEvent,
    parse_sysmon_xml,
    parse_sysmon_xml_batch,
    query_sysmon_events,
)

ProofLevel = Literal["OBSERVED", "CORRELATED", "PROVEN"]

PROXY_REGISTRY_VALUE_NAMES = (
    "ProxyEnable",
    "ProxyServer",
    "AutoConfigURL",
    "ProxyOverride",
)


@dataclass
class RegistryWriteEvidence:
    """Normalized registry write row suitable for causation and audit."""

    timestamp_utc: str
    event_source: str
    event_id: int
    registry_path: str
    registry_value_name: str
    written_value: str
    process_id: int | None
    process_guid: str | None
    image: str
    command_line: str
    user: str
    confidence: float
    proof_level: ProofLevel
    rule_name: str = ""
    details: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "timestamp_utc": self.timestamp_utc,
            "event_source": self.event_source,
            "event_id": self.event_id,
            "registry_path": self.registry_path,
            "registry_value_name": self.registry_value_name,
            "written_value": self.written_value,
            "process_id": self.process_id,
            "process_guid": self.process_guid,
            "image": self.image,
            "command_line": self.command_line,
            "user": self.user,
            "confidence": self.confidence,
            "proof_level": self.proof_level,
            "rule_name": self.rule_name,
            "details": self.details,
        }


def _proof_level_for_event(event: SysmonEvent) -> ProofLevel:
    if event.event_id == 13 and event.target_object and is_proxy_registry_target(event.target_object):
        return "PROVEN"
    if event.event_id in (12, 13):
        return "CORRELATED"
    return "OBSERVED"


def _normalize_sysmon_event(event: SysmonEvent, *, source: str = "sysmon") -> RegistryWriteEvidence | None:
    if event.event_id not in (12, 13):
        return None
    target = event.target_object or ""
    if event.event_id == 13 and not is_proxy_registry_target(target):
        return None
    value_name = proxy_registry_value_name(target) or ""
    if event.event_id == 13 and not value_name:
        return None
    proof = _proof_level_for_event(event)
    confidence = 0.95 if proof == "PROVEN" else (0.55 if proof == "CORRELATED" else 0.25)
    return RegistryWriteEvidence(
        timestamp_utc=event.utc_time,
        event_source=source,
        event_id=event.event_id,
        registry_path=target,
        registry_value_name=value_name or (target.split("\\")[-1] if target else ""),
        written_value=str(event.details or ""),
        process_id=event.process_id,
        process_guid=event.process_guid,
        image=str(event.image or ""),
        command_line=str(event.command_line or ""),
        user=str(event.user or ""),
        confidence=confidence,
        proof_level=proof,
        rule_name=str(event.rule_name or ""),
        details=str(event.details or ""),
        raw=event.to_dict(),
    )


def events_from_evtx_path(path: Path, *, run: Callable[..., Any] | None = None) -> list[SysmonEvent]:
    """Load Sysmon events from an exported ``.evtx`` file via ``wevtutil`` (Windows only)."""
    if not path.is_file() or path.suffix.lower() != ".evtx":
        return []
    if platform.system() != "Windows":
        return []
    subprocess_run = run if run is not None else subprocess.run
    try:
        proc = subprocess_run(
            ["wevtutil", "qe", str(path.resolve()), "/f:xml", "/c:512"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=120.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    xml_text = (proc.stdout or "").strip()
    if not xml_text:
        return []
    if "</Event>" in xml_text:
        chunks = [chunk + "</Event>" for chunk in xml_text.split("</Event>") if "<Event" in chunk]
        return parse_sysmon_xml_batch(chunks)
    ev = parse_sysmon_xml(xml_text)
    return [ev] if ev else []


def events_from_fixture_path(path: Path) -> list[SysmonEvent]:
    """Load Sysmon events from XML file, JSON array, or NDJSON fixture."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, dict) and "events" in data:
            rows = data["events"]
        elif isinstance(data, list):
            rows = data
        else:
            rows = [data]
        out: list[SysmonEvent] = []
        for row in rows:
            if isinstance(row, str) and row.strip().startswith("<"):
                ev = parse_sysmon_xml(row)
                if ev:
                    out.append(ev)
            elif isinstance(row, dict):
                if "xml" in row:
                    ev = parse_sysmon_xml(str(row["xml"]))
                    if ev:
                        out.append(ev)
                elif "EventID" in row or "event_id" in row:
                    pid_raw = row.get("ProcessId") or row.get("process_id")
                    pid = int(pid_raw) if pid_raw is not None and str(pid_raw).isdigit() else None
                    ev = SysmonEvent(
                        utc_time=str(row.get("UtcTime") or row.get("utc_time") or ""),
                        event_id=int(row.get("EventID") or row.get("event_id") or 0),
                        process_guid=row.get("ProcessGuid") or row.get("process_guid"),
                        process_id=pid,
                        image=row.get("Image") or row.get("image"),
                        command_line=row.get("CommandLine") or row.get("command_line"),
                        target_object=row.get("TargetObject") or row.get("target_object"),
                        details=row.get("Details") or row.get("details"),
                        user=row.get("User") or row.get("user"),
                        rule_name=row.get("RuleName") or row.get("rule_name"),
                    )
                    out.append(ev)
        return out
    if "<Event" in text:
        return parse_sysmon_xml_batch([text] if "<Event" in text and text.count("<Event") == 1 else text.split("</Event>"))
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    xml_chunks = [ln for ln in lines if ln.startswith("<")]
    if xml_chunks:
        return parse_sysmon_xml_batch(xml_chunks)
    if path.suffix.lower() == ".evtx":
        return events_from_evtx_path(path)
    return []


def load_sysmon_events(
    *,
    since_minutes: int = 30,
    run: Callable[..., Any] | None = None,
    fixture_path: Path | None = None,
    sysmon_events: Iterable[SysmonEvent] | None = None,
) -> list[SysmonEvent]:
    """Load raw Sysmon events (E1/E3/E12/E13) from fixture, EVTX, or live log."""
    if sysmon_events is not None:
        return list(sysmon_events)
    if fixture_path is not None and fixture_path.is_file():
        return events_from_fixture_path(fixture_path)
    end = datetime.now(UTC)
    start = end - timedelta(minutes=max(1, since_minutes))
    try:
        return query_sysmon_events(start, end, event_ids=(1, 3, 12, 13), run=run)
    except Exception:
        return []


def collect_registry_writer_evidence(
    *,
    since_minutes: int = 30,
    run: Callable[..., Any] | None = None,
    fixture_path: Path | None = None,
    sysmon_events: Iterable[SysmonEvent] | None = None,
) -> list[RegistryWriteEvidence]:
    """Collect normalized registry write evidence for proxy keys.

    Args:
        since_minutes: Look-back when querying live Sysmon log.
        run: Injectable subprocess runner for live queries.
        fixture_path: When set, load events from fixture instead of live log.
        sysmon_events: Pre-parsed events (tests).

    Returns:
        Rows for Event ID 12/13 matching proxy registry targets (E13 fully normalized).
    """
    events = load_sysmon_events(
        since_minutes=since_minutes,
        run=run,
        fixture_path=fixture_path,
        sysmon_events=sysmon_events,
    )

    evidence: list[RegistryWriteEvidence] = []
    for ev in events:
        if ev.event_id == 13:
            row = _normalize_sysmon_event(ev)
            if row:
                evidence.append(row)
        elif ev.event_id == 12 and ev.target_object and is_proxy_registry_target(ev.target_object):
            row = _normalize_sysmon_event(ev)
            if row:
                evidence.append(row)
    evidence.sort(key=lambda r: (r.timestamp_utc, r.registry_value_name))
    return evidence


def best_registry_writer(
    evidence: list[RegistryWriteEvidence],
) -> RegistryWriteEvidence | None:
    """Return highest-confidence proven writer, else best correlated row."""
    proven = [e for e in evidence if e.proof_level == "PROVEN"]
    if proven:
        return max(proven, key=lambda r: r.confidence)
    correlated = [e for e in evidence if e.proof_level == "CORRELATED"]
    if correlated:
        return max(correlated, key=lambda r: r.confidence)
    return evidence[0] if evidence else None

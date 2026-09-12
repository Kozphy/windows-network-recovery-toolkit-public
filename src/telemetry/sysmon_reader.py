"""Read Microsoft-Windows-Sysmon/Operational and parse XML into typed events."""

from __future__ import annotations

import json
import platform
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
DEFAULT_EVENT_IDS = (1, 3, 12, 13, 14)


@dataclass
class SysmonEvent:
    """Normalized Sysmon row — fields present depend on Event ID."""

    utc_time: str
    event_id: int
    process_guid: str | None = None
    process_id: int | None = None
    image: str | None = None
    command_line: str | None = None
    parent_process_guid: str | None = None
    parent_process_id: int | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    target_object: str | None = None
    details: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    source_ip: str | None = None
    source_port: int | None = None
    user: str | None = None
    hashes: str | None = None
    integrity_level: str | None = None
    rule_name: str | None = None
    raw_fields: dict[str, str] = field(default_factory=dict)

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
            "UtcTime": self.utc_time,
            "EventID": self.event_id,
            "ProcessGuid": self.process_guid,
            "ProcessId": self.process_id,
            "Image": self.image,
            "CommandLine": self.command_line,
            "ParentProcessGuid": self.parent_process_guid,
            "ParentProcessId": self.parent_process_id,
            "ParentImage": self.parent_image,
            "ParentCommandLine": self.parent_command_line,
            "TargetObject": self.target_object,
            "Details": self.details,
            "DestinationIp": self.destination_ip,
            "DestinationPort": self.destination_port,
            "SourceIp": self.source_ip,
            "SourcePort": self.source_port,
            "User": self.user,
            "Hashes": self.hashes,
            "IntegrityLevel": self.integrity_level,
            "RuleName": self.rule_name,
        }


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    # Sysmon sometimes uses 0x hex in Details only — ports are decimal strings
    try:
        return int(text, 0)
    except ValueError:
        return None


def _ns_strip(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def parse_sysmon_xml(xml_text: str) -> SysmonEvent | None:
    """Parse one Sysmon Event XML blob into :class:`SysmonEvent`."""
    if not xml_text or not xml_text.strip():
        return None
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    event_id: int | None = None
    utc_time = ""
    for elem in root.iter():
        tag = _ns_strip(elem.tag)
        if tag == "EventID" and elem.text:
            event_id = _parse_int(elem.text)
        elif tag == "TimeCreated" and elem.attrib.get("SystemTime"):
            utc_time = elem.attrib["SystemTime"]

    fields: dict[str, str] = {}
    for elem in root.iter():
        if _ns_strip(elem.tag) == "Data" and elem.attrib.get("Name"):
            fields[elem.attrib["Name"]] = (elem.text or "").strip()

    if event_id is None:
        event_id = _parse_int(fields.get("EventID") or fields.get("EventId"))
    if not utc_time:
        utc_time = fields.get("UtcTime") or ""

    if event_id is None:
        return None

    return SysmonEvent(
        utc_time=utc_time,
        event_id=event_id,
        process_guid=fields.get("ProcessGuid") or None,
        process_id=_parse_int(fields.get("ProcessId")),
        image=fields.get("Image") or None,
        command_line=fields.get("CommandLine") or None,
        parent_process_guid=fields.get("ParentProcessGuid") or None,
        parent_process_id=_parse_int(fields.get("ParentProcessId")),
        parent_image=fields.get("ParentImage") or None,
        parent_command_line=fields.get("ParentCommandLine") or None,
        target_object=fields.get("TargetObject") or None,
        details=fields.get("Details") or None,
        destination_ip=fields.get("DestinationIp") or None,
        destination_port=_parse_int(fields.get("DestinationPort")),
        source_ip=fields.get("SourceIp") or None,
        source_port=_parse_int(fields.get("SourcePort")),
        user=fields.get("User") or None,
        hashes=fields.get("Hashes") or None,
        integrity_level=fields.get("IntegrityLevel") or None,
        rule_name=fields.get("RuleName") or None,
        raw_fields=dict(fields),
    )


def parse_sysmon_xml_batch(xml_documents: Iterable[str]) -> list[SysmonEvent]:
    """Parse sysmon xml batch.
    
    Args:
        xml_documents: The xml documents value supplied by the caller.
    
    Returns:
        The list[SysmonEvent] result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    out: list[SysmonEvent] = []
    for doc in xml_documents:
        ev = parse_sysmon_xml(doc)
        if ev is not None:
            out.append(ev)
    return out


def _format_ps_datetime(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    local = dt.astimezone()
    return local.strftime("%Y-%m-%d %H:%M:%S")


def _powershell_query_xml(start_utc: datetime, end_utc: datetime, event_ids: tuple[int, ...]) -> str:
    ids = ",".join(str(i) for i in event_ids)
    start_s = _format_ps_datetime(start_utc)
    end_s = _format_ps_datetime(end_utc)
    return (
        "& { "
        '$ErrorActionPreference="SilentlyContinue"; '
        f"$start=[datetime]::Parse('{start_s}'); "
        f"$end=[datetime]::Parse('{end_s}'); "
        f"$ids=@({ids}); "
        "try { "
        "$ev = Get-WinEvent -FilterHashtable @{"
        f"LogName='{SYSMON_LOG}'; StartTime=$start; EndTime=$end"
        "} -MaxEvents 1000 -ErrorAction Stop | Where-Object { $ids -contains $_.Id }; "
        "$xml = @($ev | ForEach-Object { $_.ToXml() }); "
        "$xml | ConvertTo-Json -Compress "
        "} catch { Write-Output '[]' } }"
    )


def query_sysmon_events(
    start_utc: datetime,
    end_utc: datetime,
    *,
    event_ids: tuple[int, ...] | None = None,
    run: Callable[..., Any] | None = None,
    xml_documents: Iterable[str] | None = None,
) -> list[SysmonEvent]:
    """Query Sysmon Operational log between *start_utc* and *end_utc* (inclusive-ish).

    On non-Windows returns ``[]``. Tests may inject *xml_documents* to bypass PowerShell.
    """
    if xml_documents is not None:
        return parse_sysmon_xml_batch(xml_documents)

    if platform.system() != "Windows":
        return []

    ids = event_ids or DEFAULT_EVENT_IDS
    subprocess_run = run if run is not None else subprocess.run
    argv = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        _powershell_query_xml(start_utc, end_utc, ids),
    ]
    try:
        proc = subprocess_run(argv, capture_output=True, text=True, shell=False, timeout=90.0)
    except (OSError, subprocess.TimeoutExpired):
        return []

    text = (getattr(proc, "stdout", "") or "").strip()
    if not text:
        return []
    try:
        blob = json.loads(text)
    except json.JSONDecodeError:
        return []

    docs: list[str]
    if isinstance(blob, str):
        docs = [blob]
    elif isinstance(blob, list):
        docs = [x for x in blob if isinstance(x, str)]
    else:
        return []

    return parse_sysmon_xml_batch(docs)

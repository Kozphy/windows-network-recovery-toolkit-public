"""Registry writer evidence collection for WinINET proxy attribution.

This module is read-only. It queries or parses telemetry that can show a
process wrote HKCU WinINET proxy values. Registry polling and listener
correlation live elsewhere because they are observations/correlations, not
writer proof.
"""

from __future__ import annotations

import csv
import json
import platform
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

INTERNET_SETTINGS_FRAGMENT = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings".lower()
PROXY_VALUE_NAMES = frozenset(
    {
        "proxyenable",
        "proxyserver",
        "autoconfigurl",
        "proxyoverride",
        "autodetect",
    }
)
PROXY_VALUE_DISPLAY = {
    "proxyenable": "ProxyEnable",
    "proxyserver": "ProxyServer",
    "autoconfigurl": "AutoConfigURL",
    "proxyoverride": "ProxyOverride",
    "autodetect": "AutoDetect",
}
WRITER_PROOF_UNAVAILABLE = (
    "writer proof unavailable; enable Sysmon registry telemetry or import Procmon trace."
)


@dataclass(frozen=True)
class RegistryWriterEvidence:
    """Direct registry-write evidence from Sysmon, Security log, Procmon, or ETW exports.

    Attributes:
        timestamp: Event timestamp as supplied by the telemetry source.
        process_image: Executable image/path reported by the telemetry source.
        process_id: PID reported by the telemetry source when available.
        user: User reported by the telemetry source when available.
        target_object: Registry key/value path touched by the process.
        value_name: Normalized WinINET value name.
        previous_value: Previous value if telemetry provided it.
        current_value: Current/new value if telemetry provided it.
        event_source: Source code such as ``sysmon_event_13`` or ``procmon_csv``.
        source_event_id: Source event id or operation name.
        raw: Bounded original fields for audit review.
        limitations: Source-specific caveats.
    """

    timestamp: str | None
    process_image: str | None
    process_id: int | None
    user: str | None
    target_object: str
    value_name: str | None
    previous_value: str | None
    current_value: str | None
    event_source: str
    source_event_id: str | None
    raw: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.92
    limitations: list[str] = field(default_factory=list)

    def to_jsonable(self) -> dict[str, Any]:
        """Return a JSON-ready representation without mutating the evidence row."""

        return asdict(self)


def _coerce_int(value: Any) -> int | None:
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _lower_keys(row: dict[str, Any]) -> dict[str, Any]:
    return {str(k).strip().lower().replace(" ", "_"): v for k, v in row.items()}


def normalize_registry_value_name(target_object: str, fallback: str | None = None) -> str | None:
    """Return a canonical WinINET proxy value name when *target_object* is in scope.

    Args:
        target_object: Registry path or object name from telemetry.
        fallback: Optional value-name field supplied separately by a source.

    Returns:
        Canonical display value such as ``ProxyServer``, or ``None`` when the path/value is not
        one of the monitored WinINET proxy knobs.
    """

    target = str(target_object or "").replace("/", "\\")
    target_l = target.lower()
    candidate = (fallback or "").strip().lower()
    if candidate in PROXY_VALUE_NAMES:
        if target_l and INTERNET_SETTINGS_FRAGMENT not in target_l:
            return None
        return PROXY_VALUE_DISPLAY[candidate]

    if INTERNET_SETTINGS_FRAGMENT not in target_l:
        return None
    tail = target_l.split(INTERNET_SETTINGS_FRAGMENT, 1)[-1].strip("\\")
    tail_name = tail.split("\\")[-1].strip().lower()
    if tail_name in PROXY_VALUE_NAMES:
        return PROXY_VALUE_DISPLAY[tail_name]
    for value_name in PROXY_VALUE_NAMES:
        if value_name in target_l:
            return PROXY_VALUE_DISPLAY[value_name]
    return None


def is_proxy_registry_target(target_object: str, fallback_value_name: str | None = None) -> bool:
    """Return whether a registry telemetry row targets monitored WinINET proxy values."""

    return normalize_registry_value_name(target_object, fallback_value_name) is not None


def detect_sysmon_status(
    *,
    run: Callable[..., Any] = subprocess.run,
    platform_name: str | None = None,
    powershell_exe: str = "powershell.exe",
) -> dict[str, Any]:
    """Detect whether Sysmon service/log telemetry is available.

    Args:
        run: Subprocess runner injected by tests.
        platform_name: Optional platform override. Defaults to :func:`platform.system`.
        powershell_exe: PowerShell executable name/path.

    Returns:
        Dict with ``installed``, ``running``, ``service_names``, ``log_available``, and
        ``limitations``.
    """

    if (platform_name or platform.system()).lower() != "windows":
        return {
            "installed": False,
            "running": False,
            "service_names": [],
            "log_available": False,
            "limitations": ["non_windows_platform"],
        }

    script = (
        "& { "
        '$ErrorActionPreference="SilentlyContinue"; '
        "$svc=@(Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | "
        "Select-Object Name,Status); "
        "$log=$null; try { $log=Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' "
        "-ErrorAction Stop } catch { $log=$null }; "
        "$recordCount=$null; if($log){ $recordCount=$log.RecordCount }; "
        "[pscustomobject]@{"
        "services=$svc;"
        "log_available=[bool]$log;"
        "record_count=$recordCount"
        "} | ConvertTo-Json -Depth 5 -Compress "
        "}"
    )
    try:
        proc = run(
            [powershell_exe, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            errors="replace",
            shell=False,
            timeout=30.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "installed": False,
            "running": False,
            "service_names": [],
            "log_available": False,
            "limitations": [f"sysmon_status_query_failed:{type(exc).__name__}"],
        }

    if int(getattr(proc, "returncode", 1)) != 0:
        return {
            "installed": False,
            "running": False,
            "service_names": [],
            "log_available": False,
            "limitations": [
                "sysmon_status_query_nonzero",
                (getattr(proc, "stderr", "") or "")[:300],
            ],
        }

    try:
        blob = json.loads((getattr(proc, "stdout", "") or "").strip() or "{}")
    except json.JSONDecodeError:
        return {
            "installed": False,
            "running": False,
            "service_names": [],
            "log_available": False,
            "limitations": ["sysmon_status_json_parse_failed"],
        }

    services_raw = blob.get("services") if isinstance(blob, dict) else []
    if isinstance(services_raw, dict):
        services = [services_raw]
    elif isinstance(services_raw, list):
        services = [s for s in services_raw if isinstance(s, dict)]
    else:
        services = []
    service_names = [str(s.get("Name") or "") for s in services if str(s.get("Name") or "").strip()]
    running = any(str(s.get("Status") or "").lower() == "running" for s in services)
    log_available = bool(blob.get("log_available")) if isinstance(blob, dict) else False
    installed = bool(service_names or log_available)
    limitations: list[str] = []
    if not installed:
        limitations.append(WRITER_PROOF_UNAVAILABLE)
    elif not running:
        limitations.append(
            "Sysmon service is installed but not running; recent writer proof may be incomplete."
        )
    if installed and not log_available:
        limitations.append("Sysmon service found but Operational event log was not readable.")
    return {
        "installed": installed,
        "running": running,
        "service_names": service_names,
        "log_available": log_available,
        "record_count": blob.get("record_count") if isinstance(blob, dict) else None,
        "limitations": limitations,
    }


def _parse_sysmon_like_row(row: dict[str, Any]) -> RegistryWriterEvidence | None:
    lower = _lower_keys(row)
    event_id = _coerce_int(lower.get("eventid") or lower.get("event_id") or lower.get("id"))
    if event_id is not None and event_id != 13:
        return None

    target = str(
        lower.get("targetobject")
        or lower.get("target_object")
        or lower.get("target")
        or lower.get("registry_path")
        or ""
    ).strip()
    value_name = normalize_registry_value_name(target)
    if value_name is None:
        return None

    details = lower.get("details")
    raw_limited = dict(row)
    return RegistryWriterEvidence(
        timestamp=str(
            lower.get("utctime")
            or lower.get("utc_time")
            or lower.get("timecreated")
            or lower.get("timestamp")
            or ""
        )
        or None,
        process_image=str(
            lower.get("image") or lower.get("process_image") or lower.get("processpath") or ""
        ).strip()
        or None,
        process_id=_coerce_int(
            lower.get("processid") or lower.get("process_id") or lower.get("pid")
        ),
        user=str(lower.get("user") or "").strip() or None,
        target_object=target,
        value_name=value_name,
        previous_value=None,
        current_value=str(details)[:2048] if details is not None else None,
        event_source="sysmon_event_13",
        source_event_id="13",
        raw=raw_limited,
        confidence=0.94,
        limitations=[
            "Sysmon Event ID 13 supplies the set value detail; it does not always include previous value."
        ],
    )


def parse_sysmon_event_rows(rows: list[dict[str, Any]]) -> list[RegistryWriterEvidence]:
    """Parse Sysmon Event ID 13 dictionaries into writer-proof evidence rows."""

    out: list[RegistryWriterEvidence] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ev = _parse_sysmon_like_row(row)
        if ev is not None:
            out.append(ev)
    return out


def _sysmon_query_script(since_seconds: int, max_events: int) -> str:
    ss = max(1, int(since_seconds))
    mx = max(1, min(int(max_events), 1000))
    return (
        "& { "
        '$ErrorActionPreference="SilentlyContinue"; '
        f"$start=(Get-Date).AddSeconds(-{ss}); "
        "$rows=@(); "
        "try { "
        "$events=@(Get-WinEvent -FilterHashtable @{"
        "LogName='Microsoft-Windows-Sysmon/Operational';Id=13;StartTime=$start"
        f"}} -MaxEvents {mx} -ErrorAction Stop); "
        "foreach($evt in $events){ "
        "$x=[xml]$evt.ToXml(); $h=[ordered]@{}; "
        "foreach($d in @($x.Event.EventData.Data)){ $h[[string]$d.Name]=[string]$d.'#text' }; "
        "$h['EventID']='13'; $h['TimeCreated']=[string]$x.Event.System.TimeCreated.SystemTime; "
        "$rows += [pscustomobject]$h "
        "} "
        "} catch { } "
        "$rows | ConvertTo-Json -Depth 6 -Compress "
        "}"
    )


def query_sysmon_registry_writes(
    *,
    since_seconds: int = 120,
    max_events: int = 200,
    run: Callable[..., Any] = subprocess.run,
    platform_name: str | None = None,
    powershell_exe: str = "powershell.exe",
) -> dict[str, Any]:
    """Query recent Sysmon Event ID 13 rows for WinINET proxy registry writes.

    Returns:
        Dict containing ``evidence`` as :class:`RegistryWriterEvidence` objects plus
        ``limitations`` and ``sysmon_status``.
    """

    status = detect_sysmon_status(
        run=run, platform_name=platform_name, powershell_exe=powershell_exe
    )
    if not status.get("installed"):
        return {
            "evidence": [],
            "limitations": list(status.get("limitations") or [WRITER_PROOF_UNAVAILABLE]),
            "sysmon_status": status,
        }

    script = _sysmon_query_script(since_seconds, max_events)
    try:
        proc = run(
            [powershell_exe, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            errors="replace",
            shell=False,
            timeout=65.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "evidence": [],
            "limitations": [
                f"sysmon_event_query_failed:{type(exc).__name__}",
                *list(status.get("limitations") or []),
            ],
            "sysmon_status": status,
        }

    text = (getattr(proc, "stdout", "") or "").strip()
    if int(getattr(proc, "returncode", 1)) != 0:
        return {
            "evidence": [],
            "limitations": [
                "sysmon_event_query_nonzero",
                (getattr(proc, "stderr", "") or "")[:500],
                *list(status.get("limitations") or []),
            ],
            "sysmon_status": status,
        }

    try:
        parsed = json.loads(text or "[]")
    except json.JSONDecodeError:
        return {
            "evidence": [],
            "limitations": ["sysmon_event_json_parse_failed"],
            "sysmon_status": status,
        }

    if isinstance(parsed, dict):
        rows = [parsed]
    elif isinstance(parsed, list):
        rows = [r for r in parsed if isinstance(r, dict)]
    else:
        rows = []
    evidence = parse_sysmon_event_rows(rows)
    limitations = list(status.get("limitations") or [])
    if not evidence:
        limitations.append(
            "No Sysmon Event ID 13 proxy registry writes found in the requested time window."
        )
    return {"evidence": evidence, "limitations": limitations, "sysmon_status": status}


def _parse_message_pairs(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw in str(message or "").splitlines():
        line = raw.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        norm = key.strip().lower().replace(" ", "_")
        if norm:
            fields[norm] = val.strip()
    return fields


def parse_security_4657_rows(rows: list[dict[str, Any]]) -> list[RegistryWriterEvidence]:
    """Parse Windows Security Event ID 4657 registry-value modification rows.

    Security 4657 requires registry auditing/SACL configuration. This parser is best-effort
    because localized Windows messages vary.
    """

    out: list[RegistryWriterEvidence] = []
    for row in rows:
        lower = _lower_keys(row)
        event_id = _coerce_int(lower.get("eventid") or lower.get("event_id") or lower.get("id"))
        if event_id is not None and event_id != 4657:
            continue
        fields = dict(lower)
        msg = lower.get("message")
        if isinstance(msg, str):
            fields.update(_parse_message_pairs(msg))
        target = str(
            fields.get("object_name")
            or fields.get("objectname")
            or fields.get("target_object")
            or fields.get("targetobject")
            or ""
        ).strip()
        value_hint = str(
            fields.get("object_value_name")
            or fields.get("objectvaluename")
            or fields.get("value_name")
            or ""
        )
        value_name = normalize_registry_value_name(target, value_hint)
        if value_name is None:
            continue
        process_image = (
            str(
                fields.get("process_name") or fields.get("processname") or fields.get("image") or ""
            ).strip()
            or None
        )
        out.append(
            RegistryWriterEvidence(
                timestamp=str(fields.get("timecreated") or fields.get("timestamp") or "") or None,
                process_image=process_image,
                process_id=_coerce_int(
                    fields.get("process_id") or fields.get("processid") or fields.get("pid")
                ),
                user=str(
                    fields.get("subject_user_name")
                    or fields.get("subjectusername")
                    or fields.get("user")
                    or ""
                ).strip()
                or None,
                target_object=target,
                value_name=value_name,
                previous_value=str(fields.get("old_value") or fields.get("oldvalue") or "") or None,
                current_value=str(fields.get("new_value") or fields.get("newvalue") or "") or None,
                event_source="windows_security_event_4657",
                source_event_id="4657",
                raw=dict(row),
                confidence=0.90,
                limitations=[
                    "Security Event ID 4657 requires registry auditing/SACL coverage on the target key."
                ],
            )
        )
    return out


def _security_4657_script(since_seconds: int, max_events: int) -> str:
    ss = max(1, int(since_seconds))
    mx = max(1, min(int(max_events), 1000))
    return (
        "& { "
        '$ErrorActionPreference="SilentlyContinue"; '
        f"$start=(Get-Date).AddSeconds(-{ss}); "
        "$rows=@(); "
        "try { "
        "$events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4657;StartTime=$start} "
        f"-MaxEvents {mx} -ErrorAction Stop); "
        "foreach($evt in $events){ "
        "$x=[xml]$evt.ToXml(); $h=[ordered]@{}; "
        "foreach($d in @($x.Event.EventData.Data)){ $h[[string]$d.Name]=[string]$d.'#text' }; "
        "$h['EventID']='4657'; $h['TimeCreated']=[string]$x.Event.System.TimeCreated.SystemTime; "
        "$h['Message']=$evt.Message; $rows += [pscustomobject]$h "
        "} "
        "} catch { } "
        "$rows | ConvertTo-Json -Depth 6 -Compress "
        "}"
    )


def query_security_registry_writes(
    *,
    since_seconds: int = 120,
    max_events: int = 200,
    run: Callable[..., Any] = subprocess.run,
    platform_name: str | None = None,
    powershell_exe: str = "powershell.exe",
) -> dict[str, Any]:
    """Query Windows Security Event ID 4657 for audited registry value writes."""

    if (platform_name or platform.system()).lower() != "windows":
        return {
            "evidence": [],
            "limitations": [
                "Security 4657 registry audit log unavailable on non-Windows platform."
            ],
        }
    try:
        proc = run(
            [
                powershell_exe,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _security_4657_script(since_seconds, max_events),
            ],
            capture_output=True,
            text=True,
            errors="replace",
            shell=False,
            timeout=65.0,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"evidence": [], "limitations": [f"security_4657_query_failed:{type(exc).__name__}"]}
    if int(getattr(proc, "returncode", 1)) != 0:
        return {
            "evidence": [],
            "limitations": [
                "security_4657_query_nonzero",
                (getattr(proc, "stderr", "") or "")[:500],
            ],
        }
    try:
        parsed = json.loads((getattr(proc, "stdout", "") or "").strip() or "[]")
    except json.JSONDecodeError:
        return {"evidence": [], "limitations": ["security_4657_json_parse_failed"]}
    if isinstance(parsed, dict):
        rows = [parsed]
    elif isinstance(parsed, list):
        rows = [r for r in parsed if isinstance(r, dict)]
    else:
        rows = []
    evidence = parse_security_4657_rows(rows)
    limitations: list[str] = []
    if not evidence:
        limitations.append(
            "No Security Event ID 4657 proxy registry writes found; registry auditing may be disabled."
        )
    return {"evidence": evidence, "limitations": limitations}


def _norm_header(name: str) -> str:
    return name.strip().lower().replace("_", " ")


def parse_procmon_csv(path: str | Path) -> list[RegistryWriterEvidence]:
    """Parse a Procmon CSV export for proxy-related ``RegSetValue`` rows.

    Args:
        path: Procmon CSV path. The file is read-only and never modified.

    Returns:
        Registry writer evidence rows. Empty list means no matching write evidence was found
        or the file could not be read.
    """

    csv_path = Path(path)
    if not csv_path.is_file():
        return []
    try:
        handle = csv_path.open(encoding="utf-8", errors="replace", newline="")
    except OSError:
        return []

    out: list[RegistryWriterEvidence] = []
    with handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return []
        remap = {_norm_header(h): h for h in reader.fieldnames}

        def col(*names: str) -> str | None:
            for name in names:
                found = remap.get(_norm_header(name))
                if found:
                    return found
            return None

        c_time = col("time of day", "time", "date time", "utc time")
        c_proc = col("process name", "process", "image")
        c_pid = col("pid", "process id")
        c_user = col("user")
        c_op = col("operation")
        c_path = col("path", "registry path", "target object")
        c_result = col("result")
        c_detail = col("detail", "details")
        for row in reader:
            op = str(row.get(c_op or "") or "")
            if "regsetvalue" not in op.lower() and "setvalue" not in op.lower():
                continue
            result = str(row.get(c_result or "") or "")
            if result and "success" not in result.lower():
                continue
            target = str(row.get(c_path or "") or "")
            value_name = normalize_registry_value_name(target)
            if value_name is None:
                continue
            detail = str(row.get(c_detail or "") or "")
            out.append(
                RegistryWriterEvidence(
                    timestamp=str(row.get(c_time or "") or "") or None,
                    process_image=str(row.get(c_proc or "") or "") or None,
                    process_id=_coerce_int(row.get(c_pid or "")),
                    user=str(row.get(c_user or "") or "") or None,
                    target_object=target,
                    value_name=value_name,
                    previous_value=None,
                    current_value=detail[:2048] if detail else None,
                    event_source="procmon_csv",
                    source_event_id=op or "RegSetValue",
                    raw={k: str(v)[:2048] for k, v in row.items()},
                    confidence=0.88,
                    limitations=[
                        "Procmon CSV is imported operator evidence; preserve original trace for audit chain of custody.",
                        "Procmon timestamps may be local time and may not include full date.",
                    ],
                )
            )
    return out


def collect_registry_writer_evidence(
    *,
    since_seconds: int = 120,
    procmon_csv_path: str | Path | None = None,
    include_security_log: bool = True,
    run: Callable[..., Any] = subprocess.run,
    platform_name: str | None = None,
) -> dict[str, Any]:
    """Collect all available registry-writer proof sources for proxy attribution.

    The function does not claim proof when telemetry is unavailable. It returns an explicit
    limitation instructing the operator to enable Sysmon registry telemetry or import Procmon.
    """

    evidence: list[RegistryWriterEvidence] = []
    limitations: list[str] = []
    sysmon = query_sysmon_registry_writes(
        since_seconds=since_seconds,
        run=run,
        platform_name=platform_name,
    )
    evidence.extend(sysmon.get("evidence") or [])
    limitations.extend(str(x) for x in (sysmon.get("limitations") or []) if x)

    security: dict[str, Any] = {"evidence": [], "limitations": []}
    if include_security_log:
        security = query_security_registry_writes(
            since_seconds=since_seconds,
            run=run,
            platform_name=platform_name,
        )
        evidence.extend(security.get("evidence") or [])
        limitations.extend(str(x) for x in (security.get("limitations") or []) if x)

    procmon_count = 0
    if procmon_csv_path:
        procmon = parse_procmon_csv(procmon_csv_path)
        procmon_count = len(procmon)
        evidence.extend(procmon)
        if not procmon:
            limitations.append("No Procmon CSV rows matched WinINET proxy RegSetValue filters.")

    if not evidence and WRITER_PROOF_UNAVAILABLE not in limitations:
        limitations.append(WRITER_PROOF_UNAVAILABLE)

    return {
        "evidence": evidence,
        "limitations": list(dict.fromkeys(limitations)),
        "sysmon_status": sysmon.get("sysmon_status"),
        "security_log_checked": include_security_log,
        "procmon_rows_imported": procmon_count,
        "telemetry_available": bool(evidence),
        "etw_status": {
            "live_collection": "not_started",
            "limitation": "Live ETW registry tracing is not started by this safe default path; use Sysmon or imported Procmon evidence.",
        },
    }

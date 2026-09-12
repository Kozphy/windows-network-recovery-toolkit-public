"""Optional attribution from Sysmon registry events.

Without Sysmon Operational log access this helper returns ``None`` (callers downgrade to best-effort attribution).
"""

from __future__ import annotations

import base64
import json
import subprocess
from collections.abc import Callable
from typing import Any

from .models import AttributionResult, ProcessIdentity


def _sysmon_compact_script(max_events: int) -> str:
    return rf"""
$ErrorActionPreference = 'SilentlyContinue'
$list = @(try {{
  Get-WinEvent -FilterHashtable @{{
    LogName = 'Microsoft-Windows-Sysmon/Operational';
    Id = 13;
  }} -MaxEvents {max_events}
}} catch {{
  @()
}})
$results = foreach ($evt in $list) {{
  $xd = [xml]$evt.ToXml()
  $image = ''
  $processId = $null
  $targetObj = ''
  $detailsTxt = ''
  foreach ($field in @($xd.Event.EventData.Data)) {{
    switch ([string]$field.Name) {{
      'Image'       {{ $image = [string]$field.'#text' }}
      'ProcessId'   {{ try {{ $processId = [int]$field.'#text' }} catch {{ }} }}
      'TargetObject' {{ $targetObj = [string]$field.'#text' }}
      'Details'     {{ $detailsTxt = [string]$field.'#text' }}
    }}
  }}
  [pscustomobject]@{{
    UtcTime   = ([string]$xd.Event.System.TimeCreated.SystemTime)
    Image     = $image
    ProcessId = $processId
    Target    = $targetObj
    Details   = $detailsTxt
  }}
}}
$listJson = ConvertTo-Json -InputObject $results -Compress -Depth 4
$listJson | Write-Output
""".strip()


def _looks_like_proxy_registry(fields: dict[str, Any]) -> bool:
    tgt = str(fields.get("Target") or "")
    blob = (
        tgt
        + " "
        + str(fields.get("Details") or "").lower()
    ).lower()
    return "internet settings" in tgt.lower() or "internet settings" in blob


def attribution_from_windows_event_logs(
    *,
    run: Callable[..., Any] = subprocess.run,
    mode: str,
    max_events: int = 10,
    powershell_exe: str = "powershell.exe",
) -> AttributionResult | None:
    """Return attribution derived from Sysmon Event ID **13**, or ``None`` if unreachable."""

    m = mode.strip().lower()
    if m == "best-effort":
        return None
    script = _sysmon_compact_script(max_events=max_events).encode("utf-16-le")
    encoded = base64.b64encode(script).decode("ascii")
    argv = [
        powershell_exe,
        "-NoProfile",
        "-NonInteractive",
        "-STA",
        "-EncodedCommand",
        encoded,
    ]
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=50)
    except (OSError, subprocess.TimeoutExpired):
        return None
    stdout = (proc.stdout or "").strip()
    if not stdout:
        return None
    try:
        rows = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if isinstance(rows, dict):
        rows_iter = [rows]
    elif isinstance(rows, list):
        rows_iter = [r for r in rows if isinstance(r, dict)]
    else:
        return None

    latest: dict[str, Any] | None = None
    for row in rows_iter:
        if _looks_like_proxy_registry(row):
            latest = row
    if latest is None:
        return None

    image = latest.get("Image")
    pid = latest.get("ProcessId")

    pid_i = int(pid) if isinstance(pid, int) else None
    pid_i_try = pid_i
    if pid_i_try is None and isinstance(pid, str) and pid.isdigit():
        pid_i_try = int(pid)

    proc = ProcessIdentity(
        pid=pid_i_try,
        ppid=None,
        exe=str(image).strip('"') if image else None,
        name=None,
        cmdline=None,
        create_time_utc=str(latest.get("UtcTime") or "") or None,
        user=None,
        source="eventlog_sysmon_registry",
    )

    evidence = ("sysmon_eid13_registry_write_correlated",)
    limitations = ("requires_auditing_or_sysmon_and_operator_log_read_rights",)

    return AttributionResult(
        mode="verified_eventlog",
        confidence="verified",
        process=proc,
        evidence=evidence,
        limitations=limitations,
    )

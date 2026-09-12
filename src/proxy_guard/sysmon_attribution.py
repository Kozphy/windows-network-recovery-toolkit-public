"""Query Sysmon Event ID 13 (registry ``SetValue``) for HKCU WinINET proxy-related keys.

Module responsibility:
    Parse Sysmon ``Message`` text into fields, classify rows that touch proxy value names under Internet
    Settings, and optionally call ``powershell.exe`` + ``Get-WinEvent`` to read ``Microsoft-Windows-Sysmon/Operational``.
    Outputs are :class:`~src.proxy_guard.attribution_model.AttributionEvidence` rows consumed by layered
    attribution—not malware verdicts.

System placement:
    Live Windows companion to offline :mod:`evidence.sysmon_reader` (dict/CSV ingest). Imported only from
    proxy-guard attribution paths when operators enable Sysmon-backed enrichment.

Key invariants:
    * Non-Windows hosts never touch PowerShell—return diagnostic ``unknown`` evidence immediately.
    * ``collect_sysmon_proxy_events`` avoids raising—transport, JSON, or ACL failures degrade to explanatory evidence.

Input assumptions:
    ``Message`` bodies follow Sysmon ``Key: value`` line conventions typical of localized installs; parsers
    normalize keys to lowercase underscored tokens.

Output guarantees:
    Return list is never empty after ``collect_sysmon_proxy_events``: either actionable proxy rows or a single
    diagnostic ``unknown`` / zero-hit note.

Timezone:
    ``TimeCreated`` from ``Get-WinEvent``, when serialized to JSON objects, attempts UTC ``strftime``; string
    pass-through preserves exporter text verbatim.

Duplicates / malformed:
    Repeated EID13 rows enumerate individually; malformed JSON yields ``collector_malformed_json`` hints.

Side effects:
    ``collect_sysmon_proxy_events`` invokes ``powershell.exe`` with ``-NonInteractive``, ``timeout=65s``, and
    may read operational security logs (~200 max events).

Idempotency:
    Read-only—duplicate calls widen operator log noise only.

Failure modes:
    Missing Sysmon operational log, access denied stderr, timeouts, empty windows → structured ``notes`` chains.

Recovery guidance:
    Confirm Sysmon installed and Operational log readable; widen ``since_seconds``; capture stderr snippets from
    returned evidence.

Audit Notes:
    Persist returned ``AttributionEvidence`` next to polled registry snapshots—timelines must align for contested
    ``ProxyEnable`` flips.

Engineering Notes:
    ``pytest`` passes inject ``run=`` stubs to bypass live ``subprocess``.
"""

from __future__ import annotations

import json
import platform
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .attribution_model import AttributionEvidence

_INTERNET_SETTINGS_FRAGMENT = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings".lower()
_PROXY_VALUES = frozenset(
    {
        "proxyenable",
        "proxyserver",
        "autoconfigurl",
        "autodetect",
        "proxyoverride",
    },
)


def _utc_now_compact() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_sysmon_e13_message(message: str) -> dict[str, str]:
    """Parse common ``Key: value`` lines embedded in Sysmon Event 13 ``Message`` text.

    Args:
        message: Raw event Message field (may span multiple lines).

    Returns:
        Lowercase underscore keys mapped to trimmed string values.

    Raises:
        None — always returns a dict (possibly empty).
    """
    out: dict[str, str] = {}
    if not isinstance(message, str) or not message.strip():
        return out
    for raw_line in message.splitlines():
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        k = key.strip().lower().replace(" ", "_")
        if not k:
            continue
        out[k] = val.strip()
    return out


def proxy_target_from_sysmon_fields(fields: dict[str, str]) -> tuple[str | None, str | None]:
    """Resolve WinINET proxy value atom and Sysmon TargetObject substring from parsed fields.

    Args:
        fields: Output of :func:`parse_sysmon_e13_message` (lowercase underscored keys).

    Returns:
        ``(logical_key, target_display)`` where ``logical_key`` is one of monitored value names such as
        ``proxyenable`` when under Internet Settings, else ``None`` when not proxy-scoped.

    Limitations:
        Accepts abbreviated paths via substring match—may correlate broadly named keys; pair with reviewer judgment.
    """

    tgt = ""
    for k in ("targetobject", "target_object", "regobjectname"):
        if k in fields:
            tgt = fields[k]
            break
    if not tgt:
        return None, None
    low = tgt.lower()
    if _INTERNET_SETTINGS_FRAGMENT not in low.replace("/", "\\"):
        return None, tgt
    tail = low.split(_INTERNET_SETTINGS_FRAGMENT, 1)[-1].strip("\\/")
    atom = tail.split("\\")[-1].split("/")[-1].strip().lower().rstrip(":")
    if atom in _PROXY_VALUES:
        return atom, tgt
    for pv in _PROXY_VALUES:
        if pv in low:
            return pv, tgt
    return None, tgt


def attribution_evidence_from_sysmon_message(
    message: str,
    *,
    time_created_hint: str | None = None,
) -> AttributionEvidence | None:
    """Build high-confidence Sysmon attribution evidence when proxy registry writes are identifiable.

    Args:
        message: Raw Sysmon EID13 ``Message`` body.
        time_created_hint: Optional timestamp string bound to exporter row ordering.

    Returns:
        Hydrated evidence with ``source="sysmon_event_13"``, or ``None`` when parsing finds no proxy value.

    Side effects:
        None.

    Audit Notes:
        ``confidence_score`` reflects structured log observation strength—not independent corroboration from other sensors.
    """

    fields = parse_sysmon_e13_message(message)
    vk, tgt = proxy_target_from_sysmon_fields(fields)
    if vk is None:
        return None
    pid_s = fields.get("processid") or fields.get("process_id") or ""
    pid: int | None = None
    if pid_s.strip().isdigit():
        pid = int(pid_s.strip())
    details = fields.get("details") or ""
    raw = dict(fields)
    raw["_parsed_target_ok"] = True
    return AttributionEvidence(
        source="sysmon_event_13",
        observed_at=time_created_hint,
        event_id="13",
        target_key=tgt,
        target_value_name=vk,
        new_value=str(details or "")[:2048] or None,
        raw_excerpt={
            "image": fields.get("image"),
            "process_id": pid,
            "user": fields.get("user"),
            "target_object": tgt,
            "details": str(details or "")[:2048],
            "rule_name": fields.get("rulename") or fields.get("rule_name"),
        },
        confidence_score=0.92,
        notes=[
            "Sysmon Event ID 13 observed registry SetValue on WinINET proxy-related key",
            "Direct observation of registry write path on this host — correlate UtcTime/Message for audits",
        ],
    )


def _powershell_sysmon_json(since_seconds: int) -> str:
    """Build a compact PowerShell script body that emits JSON via ``ConvertTo-Json`` (silent empty array on error).

    Security / audit:
        Uses literal filter on Sysmon Operational log ``Id=13`` only; emits at most ``-MaxEvents 200`` compressed JSON.
        Callers invoke via ``powershell.exe -NoProfile -NonInteractive`` without ``shell=True``.

    Escaping:
        ``since_seconds`` coerced via ``max(1, int(...))`` for safe embedding inside emitted ``AddSeconds``.
    """

    ss = max(1, int(since_seconds))
    return (
        "& { "
        '$ErrorActionPreference="SilentlyContinue"; '
        f"$start=(Get-Date).AddSeconds(-{ss}); "
        "try { "
        "$ev = Get-WinEvent -FilterHashtable @{"
        "LogName='Microsoft-Windows-Sysmon/Operational';"
        " Id=13;"
        " StartTime=$start"
        "} -MaxEvents 200 -ErrorAction Stop; "
        "$ev | Select-Object TimeCreated, Id, Message | ConvertTo-Json -Depth 4 -Compress "
        "} catch { Write-Output '[]' } }"
    )


def collect_sysmon_proxy_events(
    since_seconds: int = 60,
    *,
    run: Callable[..., Any] | None = None,
) -> list[AttributionEvidence]:
    """Query Sysmon Operational log for Event 13 affecting WinINET proxy keys.

    Args:
        since_seconds: Rolling look-back from local clock for ``Get-WinEvent``.
        run: Injectable ``subprocess.run`` surrogate (tests).

    Returns:
        Non-empty ``list`` — either proxy-aligned Sysmon observations or explanatory ``unknown`` diagnostics.

    Raises:
        None intentional—disk or interpreter failures propagate only if injecting a broken ``run`` stub.

    Audit Notes:
        Review ``stderr`` snippets embedded in degraded rows when Operational log denies readers; escalate with
        event viewer exports before changing scoring.

    Constraints:
        Windows-only live path—CI on Linux relies on mocks for ``collect_sysmon_proxy_events``.
    """
    subprocess_run = run if run is not None else subprocess.run
    if platform.system() != "Windows":
        return [
            AttributionEvidence(
                source="unknown",
                confidence_score=0.0,
                notes=[
                    "Sysmon log unavailable",
                    "Operating system does not expose Microsoft-Windows-Sysmon/Operational",
                ],
            ),
        ]

    argv = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _powershell_sysmon_json(since_seconds)]
    blob: Any = None
    try:
        proc = subprocess_run(argv, capture_output=True, text=True, shell=False, timeout=65.0)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [
            AttributionEvidence(
                source="unknown",
                confidence_score=0.0,
                notes=["Sysmon log unavailable", f"collector_subprocess_failure:{type(exc).__name__}"],
            ),
        ]

    stdout = getattr(proc, "stdout", "") or ""
    stderr = getattr(proc, "stderr", "") or ""
    text = stdout.strip()
    if not text and stderr.strip():
        return [
            AttributionEvidence(
                source="unknown",
                confidence_score=0.0,
                notes=[
                    "Sysmon log unavailable",
                    "access_denied_or_log_missing_hint",
                    stderr.strip()[:500],
                ],
            ),
        ]
    try:
        blob = json.loads(text or "[]")
    except json.JSONDecodeError:
        return [
            AttributionEvidence(
                source="unknown",
                confidence_score=0.0,
                notes=["Sysmon log unavailable", "collector_malformed_json"],
            ),
        ]

    rows: list[dict[str, Any]]
    if isinstance(blob, dict):
        rows = [blob]
    elif isinstance(blob, list):
        rows = [x for x in blob if isinstance(x, dict)]
    else:
        return [
            AttributionEvidence(
                source="unknown",
                confidence_score=0.0,
                notes=["Sysmon log unavailable", "unexpected_powershell_json_shape"],
            ),
        ]

    out: list[AttributionEvidence] = []
    for row in rows:
        msg = row.get("Message")
        if not isinstance(msg, str):
            continue
        tc = row.get("TimeCreated")
        time_hint: str | None = None
        if isinstance(tc, str):
            time_hint = tc
        elif hasattr(tc, "strftime"):
            try:
                time_hint = tc.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (OSError, ValueError):
                time_hint = str(tc)
        ev = attribution_evidence_from_sysmon_message(msg, time_created_hint=time_hint or _utc_now_compact())
        if ev is not None:
            out.append(ev)

    if not out:
        return [
            AttributionEvidence(
                source="sysmon_event_13",
                confidence_score=0.0,
                notes=["No proxy registry SetValue event found in window"],
            ),
        ]
    return out

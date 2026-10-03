"""Project Sysmon Event ID 13 rows into attribution tuples.

Module responsibility:
    Accept pre-normalized dict rows (CSV exports, SIEM snippets) representing **registry value set**
    events Sysmon emits as ``EventID`` 13, then filter targets relevant to Internet Settings proxies.

System placement:
    Upstream collectors must supply dictionaries—there is **no** Windows Event Log subscription here.

Key invariants:
    * Only numeric event id ``13`` rows instantiate :class:`SysmonRegistrySetEvent`.
    * ``Image`` equals process path semantics from Sysmon; treat as attacker-controlled formatting.

Timezone:
    ``utc_time`` is stored as verbatim string extracted from exporters—caller normalizes TZ if needed.

Failure modes:
    :func:`parse_sysmon_row` returns ``None`` for irrelevant IDs or wholly empty payloads—never raises.

Audit Notes:
    Pair parsed rows with diff timelines from registry polling; discrepancy indicates delayed export or rotated logs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SysmonRegistrySetEvent:
    """Subset of Sysmon EID13 attributes needed for attribution.

    Attributes:
        event_id: Always ``13`` when emitted by parser.
        image: Reporting process path—may omit quotes from exporter.
        target_object: Sysmon TargetObject/registry path substring.
        details: Serialized value detail string when present.
        utc_time: Optional ISO-ish timestamp string from exporter.
    """

    event_id: int
    image: str
    target_object: str
    details: str = ""
    utc_time: str | None = None


def _coerce_int(v: Any) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def parse_sysmon_row(row: dict[str, Any]) -> SysmonRegistrySetEvent | None:
    """Validate and materialize one Sysmon-style mapping.

    Args:
        row: Keys may include ``EventID``, ``Image``, ``TargetObject`` (case variants tolerated).

    Returns:
        Instantiated event when ID is registry-set (13 here) and at least one of image/target exists.

    Constraints:
        Non-registry Sysmon IDs return ``None`` quietly to keep iterators simple.
    """

    eid = _coerce_int(row.get("EventID") or row.get("Id") or row.get("event_id"))
    if eid not in (13,):
        return None
    img = str(row.get("Image") or row.get("ProcessPath") or row.get("image") or "").strip()
    obj = str(
        row.get("TargetObject") or row.get("target_object") or row.get("RegistryPath") or "",
    ).strip()
    if not img and not obj:
        return None
    detail = str(row.get("Details") or row.get("details") or "")
    utc = row.get("UtcTime") or row.get("timestamp")
    utc_s = None if utc is None else str(utc)
    return SysmonRegistrySetEvent(
        event_id=13,
        image=img,
        target_object=obj,
        details=detail,
        utc_time=utc_s,
    )


def registry_event_concerns_internet_settings(ev: SysmonRegistrySetEvent) -> bool:
    """Heuristically flag rows touching WinINET/PAC proxy knobs.

    Args:
        ev: Parsed Sysmon row.

    Returns:
        ``True`` when ``TargetObject`` substrings resemble ``Internet Settings`` or explicit proxy entries.

    Limitations:
        Locale-specific registry aliases or abbreviated paths might false-negative—manual review retains precedence.
    """

    t = ev.target_object.lower()
    needles = ("internet settings", "proxyenable", "proxyserver", "\\proxy")
    return any(n in t for n in needles)

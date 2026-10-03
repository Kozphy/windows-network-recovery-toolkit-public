"""Fuse heterogeneous telemetry into a ranked :class:`~evidence.models.AttributionResult`.

Module responsibility:
    Consume registry diff hints, contemporaneous listeners/process guesses, optional Sysmon/Procmon/ETW
    exports, emit confidence + enumerated ``attribution_level`` consistent with forensic humility rules.

Decision intent:
    * Elevate tiers only when structured telemetry corroborates a writer image/path.
    * Cap claims at ``heuristic`` when only polling/process correlation exists—encoded via explicit ``Honest_boundary`` note text.

Inputs:
    Plain dict / sequence structures already normalized by exporters; callers must strip secrets beforehand.

Outputs:
    Deterministic scoring for identical inputs on same interpreter version—float ordering stable enough for regression tests.

Side effects:
    None—serialization happens in API layer when persisting.

Idempotency:
    Pure functional core; retries simply recompute duplicate logical results.

Raises:
    None from public helpers.

Constraints:
    Confidence is portfolio heuristic—not calibrated ML probability—document when presenting to executives.

Audit Notes:
    Persist resulting ``AttributionResult`` JSON alongside raw evidence imports to replay disputes; deltas between runs usually mean upstream context rows changed—not silent engine mutation.

Engineering Notes:
    Lightweight linear scoring trades accuracy for transparency—alternate ML rankers intentionally avoided for audit defensibility.

Examples:
    See ``tests/test_evidence_pipeline.py`` for heuristic-only vs Sysmon-augmented expectations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from evidence.models import AttributionLevel, AttributionResult, EvidenceItem
from evidence.procmon_importer import ProcmonRegistryWrite, procmon_concerns_proxy
from evidence.registry_event_parser import describe_diff, parse_registry_hint
from evidence.sysmon_reader import (
    SysmonRegistrySetEvent,
    parse_sysmon_row,
    registry_event_concerns_internet_settings,
)


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


def _inventory_actor(process_inventory: Mapping[str, Any] | None) -> str:
    if not process_inventory:
        return "unknown"
    for key in ("candidate_name", "exe_name", "process_name", "name", "Image"):
        v = process_inventory.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "unknown"


def _parent_hint(parent_process: Mapping[str, Any] | None) -> str:
    if not parent_process:
        return ""
    for key in ("parent_name", "parent_image", "name"):
        v = parent_process.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _listener_match(
    listeners: Sequence[Mapping[str, Any]] | None, proxy_server: str | None
) -> bool:
    """Return True when listener rows align with embedded ``proxy_server`` port tokens.

    Args:
        listeners: Sequence of mappings containing ``port``/``ListenPort``/``lport`` + optional IP keys.
        proxy_server: Textual ProxyServer registry value substring (may encode ``127.0.0.1:NNNN`` patterns).

    Returns:
        Positive correlation when localhost listener matches textual port presence.

    Limitations:
        IPv6 literals or PAC-based flows without explicit ProxyServer bypass this matcher silently.
    """

    if not listeners or not proxy_server:
        return False
    ps = proxy_server.lower()
    for ln in listeners:
        port = str(ln.get("port") or ln.get("lport") or ln.get("ListenPort") or "")
        addr = str(ln.get("address") or ln.get("addr") or ln.get("ip") or "").lower()
        if not port:
            continue
        if f":{port}" in ps or ps.endswith(f":{port}") or f"127.0.0.1:{port}" in ps:
            if not addr or addr in ("127.0.0.1", "0.0.0.0", "::", ""):
                return True
    return False


def build_attribution(
    *,
    event_id: str,
    failure_summary: str = "",
    registry_context: dict[str, Any] | None = None,
    process_inventory: Mapping[str, Any] | None = None,
    parent_process: Mapping[str, Any] | None = None,
    listeners: Sequence[Mapping[str, Any]] | None = None,
    sysmon_events: Sequence[SysmonRegistrySetEvent] | None = None,
    procmon_rows: Sequence[ProcmonRegistryWrite] | None = None,
    etw_events: Sequence[dict[str, Any]] | None = None,
) -> AttributionResult:
    """Compute structured attribution respecting telemetry strength boundaries.

    Lacking Sysmon/Procmon rows, expect ``heuristic`` or ``listener_match`` tiers with explanatory text;
    optional ETW dictionaries may elevate to ``etw_confirmed`` when keyword heuristics align (see body).

    Args:
        event_id: Correlates to platform :class:`~platform_core.models.FailureEvent`.
        failure_summary: Redacted synopsis concatenated into ``notes``.
        registry_context: ``{"before": {...}, "after": {...}}`` style fixture dict.
        process_inventory: Heuristic map containing keys like ``process_name``.
        parent_process: Optional ancestry hints.
        listeners: Lightweight netstat-style sequence (dict rows).
        sysmon_events: Parsed Sysmon EID13 events.
        procmon_rows: Parsed Procmon registry writes.
        etw_events: ETW-shaped dict list (possibly empty).

    Returns:
        Hydrated :class:`~evidence.models.AttributionResult` with enumerated evidence backlog.

    Failure modes:
        Missing optional sequences degrade gracefully—never raise; weaker tiers + explanatory notes instead.

    How to audit:
        Diff ``evidence`` list ordering + ``notes`` text against contemporaneous syslog/SIEM dumps.
    """

    evidence: list[EvidenceItem] = []
    hint = parse_registry_hint(registry_context)
    reg_desc = describe_diff(hint)
    evidence.append(EvidenceItem(source="registry_poll", detail=reg_desc, weight_hint=0.15))

    inv_actor = _inventory_actor(process_inventory if isinstance(process_inventory, dict) else None)
    if inv_actor != "unknown":
        evidence.append(
            EvidenceItem(
                source="proc_inventory",
                detail=f"inventory_suggests_actor={inv_actor}",
                weight_hint=0.2,
            ),
        )

    parent = _parent_hint(parent_process if isinstance(parent_process, dict) else None)
    if parent:
        evidence.append(
            EvidenceItem(source="parent_process", detail=f"parent={parent}", weight_hint=0.1)
        )

    proxy_server = hint.proxy_server_after or hint.proxy_server_before
    if _listener_match(listeners, proxy_server):
        evidence.append(
            EvidenceItem(
                source="listener_match",
                detail="localhost_listener_aligns_with_proxy_server_token",
                weight_hint=0.25,
            ),
        )

    has_structured_telemetry = bool(sysmon_events or procmon_rows or etw_events)

    score = 0.18
    if reg_desc != "no_proxy_key_delta_in_hint":
        score += 0.12
    if inv_actor != "unknown":
        score += 0.18
    if parent:
        score += 0.06
    if _listener_match(listeners, proxy_server):
        score += 0.22

    level: AttributionLevel = "unknown"
    candidate = inv_actor if inv_actor != "unknown" else "unknown"
    notes: list[str] = []
    if failure_summary:
        notes.append(failure_summary[:240])

    confirmed_image: str | None = None

    if sysmon_events:
        for ev in sysmon_events:
            if not registry_event_concerns_internet_settings(ev):
                continue
            img = ev.image.strip()
            if img:
                confirmed_image = img
                evidence.append(
                    EvidenceItem(
                        source="sysmon",
                        detail=f"EID13 image={img!r} target={ev.target_object[:120]}",
                        weight_hint=0.55,
                    ),
                )
                break

    if procmon_rows:
        for row in procmon_rows:
            if not procmon_concerns_proxy(row):
                continue
            pn = row.process_name.strip() or "(unnamed)"
            confirmed_image = confirmed_image or pn
            evidence.append(
                EvidenceItem(
                    source="procmon",
                    detail=f"RegWrite proc={pn!r} path={row.path[:160]}",
                    weight_hint=0.45,
                ),
            )
            break

    if etw_events:
        for ee in etw_events:
            blob = str(ee)
            if "proxy" not in blob.lower():
                continue
            evidence.append(EvidenceItem(source="etw", detail=str(ee)[:200], weight_hint=0.35))
            confirmed_image = confirmed_image or "etw_process_hint"
            break

    if confirmed_image:
        candidate = confirmed_image.split("\\")[-1] if "\\" in confirmed_image else confirmed_image
        score += 0.28
        if sysmon_events and any(
            registry_event_concerns_internet_settings(s) for s in sysmon_events
        ):
            level = "sysmon_confirmed"
            score += 0.12
            notes.append(
                "Structured telemetry (Sysmon registry) corroborates a writer image path — not a malware verdict.",
            )
        elif procmon_rows:
            level = "procmon_confirmed"
            score += 0.05
            notes.append("Procmon registry write rows corroborate a writing process name.")
        else:
            level = "etw_confirmed"
            notes.append(
                "ETW-shaped evidence corroborates registry/proxy-adjacent activity; weaker than Sysmon EID13.",
            )

    elif has_structured_telemetry:
        level = "heuristic"
        score += 0.05
        notes.append(
            "Telemetry rows present but did not correlate to proxy registry targets; score capped.",
        )
    elif _listener_match(listeners, proxy_server):
        level = "listener_match"
        notes.append(
            "Listener port aligns with ProxyServer tokens — correlation only; does not identify the registry writer.",
        )
    else:
        level = "heuristic"
        notes.append(
            "Honest_boundary: registry polling and process correlation cannot prove registry writer; "
            "add Sysmon (EID13) or Procmon RegSetValue exports to raise confidence.",
        )

    score = _clamp01(score)
    if level == "unknown":
        level = "heuristic"

    return AttributionResult(
        event_id=event_id,
        candidate_actor=candidate,
        confidence=score,
        attribution_level=level,
        evidence=evidence,
        notes=" ".join(notes).strip(),
    )


def parse_sysmon_sequence(rows: Sequence[dict[str, Any]]) -> list[SysmonRegistrySetEvent]:
    """Map heterogeneous dict iterable to concrete Sysmon events (non-13 rows skipped).

    Args:
        rows: Sequence of exporter/json dicts.

    Returns:
        Possibly empty list—callers iterate without None checks.

    Side effects:
        Allocates fresh list each invocation.

    Complexity:
        O(n) over row count acceptable for fixtures (<100 rows typical offline).
    """

    out: list[SysmonRegistrySetEvent] = []
    for r in rows:
        ev = parse_sysmon_row(dict(r))
        if ev is not None:
            out.append(ev)
    return out

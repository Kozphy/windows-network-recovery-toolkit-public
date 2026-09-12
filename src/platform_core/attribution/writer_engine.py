"""Proxy Attribution Engine — registry monitoring, Sysmon/ETW fusion, process enrichment.

Module responsibility:
    Correlates Windows proxy registry writes with the originating process by fusing three
    evidence sources: live WinINET/WinHTTP registry state (collected via ``collector``),
    Sysmon Event 13 (registry-value-set) telemetry, and CIM/Win32_Process process-tree
    enrichment.  Produces a ``ProxyWriterAttributionResult`` with an ordinal confidence
    tier (VERY_LOW … VERY_HIGH) and a numeric score.  All collection is read-only;
    remediation decisions are left to callers.

Typical usage:
    result = run_proxy_writer_attribution(inject=fixture)   # deterministic from fixture
    result = run_proxy_writer_attribution(timeout=20.0)     # live collection on Windows

Limitations:
    - Sysmon E13 correlation is correlational, not causal proof; see ``attribution_tier``.
    - CIM process queries require the caller to run on Windows with appropriate privileges.
    - ``inject`` bypasses all live collection; fixture must be a valid
      ``ProxyWriterAttributionResult`` dict.
"""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.correlation.proxy_causation import analyze_proxy_causation
from src.telemetry.registry_targets import is_proxy_registry_target, proxy_registry_value_name
from src.telemetry.sysmon_reader import SysmonEvent

from .collector import collect_attribution, resolve_listener_process
from .models import ListenerClassification, ProcessAttribution
from .writer_models import (
    AttributionConfidence,
    ProxyWriterAttributionResult,
    RegistryWriterEvidence,
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_sha256(hashes: str | None) -> str:
    if not hashes:
        return ""
    for part in hashes.split(","):
        part = part.strip()
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].strip()
    return ""


def _enrich_process(
    pid: int | None,
    *,
    run: Callable[..., Any],
    timeout: float,
) -> ProcessAttribution:
    if pid is None:
        return ProcessAttribution()
    proc, _ = resolve_listener_process(None, run=run, timeout=timeout)
    # resolve_listener_process needs port; use CIM directly for pid
    import json

    ps = (
        f'$p=Get-CimInstance Win32_Process -Filter "ProcessId={pid}";'
        f'$pp=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue;'
        f"$sig=Get-AuthenticodeSignature -FilePath $p.ExecutablePath -ErrorAction SilentlyContinue;"
        f"@{{Path=$p.ExecutablePath;Cmd=$p.CommandLine;Name=$p.Name;Parent=$p.ParentProcessId;"
        f"ParentName=$pp.Name;ParentCmd=$pp.CommandLine;Sig=$sig.Status}} | ConvertTo-Json -Compress"
    )
    try:
        proc_run = run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
        out = (proc_run.stdout or "").strip()
        if out.startswith("{"):
            row = json.loads(out)
            return ProcessAttribution(
                pid=pid,
                parent_pid=int(row["Parent"]) if row.get("Parent") else None,
                executable_path=str(row.get("Path") or ""),
                command_line=str(row.get("Cmd") or ""),
                process_name=str(row.get("Name") or ""),
                signature_status=str(row.get("Sig") or ""),
            )
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, TypeError, ValueError):
        pass
    return ProcessAttribution(pid=pid)


def _sysmon_to_writer_evidence(
    ev: SysmonEvent, *, source: str, details_match: bool
) -> RegistryWriterEvidence:
    image = ev.image or ""
    parent = ev.parent_image or ""
    return RegistryWriterEvidence(
        source=source,
        event_id=ev.event_id,
        timestamp_utc=ev.utc_time,
        target_object=ev.target_object or "",
        value_name=proxy_registry_value_name(ev.target_object or "") or "",
        details=ev.details or "",
        process_name=image.split("\\")[-1] if image else "",
        pid=ev.process_id,
        ppid=ev.parent_process_id,
        parent_process_name=parent.split("\\")[-1] if parent else "",
        command_line=ev.command_line or "",
        parent_command_line=ev.parent_command_line or "",
        executable_path=image,
        sha256=_parse_sha256(ev.hashes),
        process_guid=ev.process_guid or "",
        details_match=details_match,
    )


def _score_confidence(
    *,
    writer_confirmed: bool,
    details_match: bool,
    listener_pid: int | None,
    writer_pid: int | None,
) -> tuple[AttributionConfidence, float]:
    if writer_confirmed and details_match:
        return AttributionConfidence.VERY_HIGH, 0.92
    if writer_confirmed:
        return AttributionConfidence.HIGH, 0.78
    if listener_pid and writer_pid and listener_pid == writer_pid:
        return AttributionConfidence.MEDIUM, 0.55
    if listener_pid:
        return AttributionConfidence.LOW, 0.35
    return AttributionConfidence.VERY_LOW, 0.15


def run_proxy_writer_attribution(
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 20.0,
    inject: dict[str, Any] | None = None,
    inject_sysmon: list[dict[str, Any]] | None = None,
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
    transition_timestamp: str | None = None,
    repo_root: Path | None = None,
) -> ProxyWriterAttributionResult:
    """Collect proxy state, ingest Sysmon E13 when available, correlate with process tree."""
    if inject:
        return ProxyWriterAttributionResult.model_validate(inject)

    run_fn = run or subprocess.run
    snapshot = collect_attribution(run=run_fn, timeout=timeout)
    ps = snapshot.proxy_state

    from windows_network_toolkit.collectors.proxy_registry_collector import collect_proxy_registry

    reg = collect_proxy_registry(run=run_fn)
    registry_state = {
        "ProxyEnable": reg.get("proxy_enable"),
        "ProxyServer": reg.get("proxy_server"),
        "ProxyOverride": reg.get("proxy_override"),
        "AutoConfigURL": reg.get("auto_config_url"),
    }

    limitations = [
        "Listener correlation is not registry-writer proof without Sysmon Event ID 13.",
        "Confidence is ordinal — not a malware verdict or legal certainty.",
        "ETW/registry telemetry may be unavailable on this endpoint.",
    ]
    telemetry_sources: list[str] = ["wininet_registry", "netstat", "tasklist"]
    writer_rows: list[RegistryWriterEvidence] = []

    sysmon_events: list[SysmonEvent] | None = None
    if inject_sysmon is not None:
        sysmon_events = [SysmonEvent(**row) for row in inject_sysmon]
        telemetry_sources.append("sysmon_fixture")
    elif before_state and after_state:
        causation = analyze_proxy_causation(
            timestamp_utc=transition_timestamp or _now(),
            before_state=before_state,
            after_state=after_state,
            observed_localhost_port=ps.localhost_port,
            listener_process=snapshot.listener.model_dump() if snapshot.listener.pid else None,
            run=run_fn,
            repo_root=repo_root,
            sysmon_events=sysmon_events,
        )
        telemetry_sources.append("sysmon_e13")
        for ev_dict in causation.registry_events:
            ev = SysmonEvent(
                utc_time=str(ev_dict.get("UtcTime", "")),
                event_id=int(ev_dict.get("EventID", 13)),
                process_id=ev_dict.get("ProcessId"),
                image=ev_dict.get("Image"),
                command_line=ev_dict.get("CommandLine"),
                parent_process_id=ev_dict.get("ParentProcessId"),
                parent_image=ev_dict.get("ParentImage"),
                parent_command_line=ev_dict.get("ParentCommandLine"),
                target_object=ev_dict.get("TargetObject"),
                details=ev_dict.get("Details"),
                hashes=ev_dict.get("Hashes"),
                process_guid=ev_dict.get("ProcessGuid"),
            )
            match = bool(ev_dict.get("details_match"))
            writer_rows.append(
                _sysmon_to_writer_evidence(ev, source="sysmon_e13", details_match=match)
            )

        writer_confirmed = causation.causation_level in {"FINAL_CAUSATION", "STRONG_CAUSATION"}
        classification = causation.classification
        rationale = causation.explanation
        confidence = causation.confidence
        attr_conf = (
            AttributionConfidence.VERY_HIGH
            if writer_confirmed and confidence >= 0.85
            else AttributionConfidence.HIGH
            if writer_confirmed
            else AttributionConfidence.MEDIUM
            if causation.causation_level == "CORRELATION_ONLY"
            else AttributionConfidence.LOW
        )
        correlated = snapshot.listener
        if causation.writer_pid:
            correlated = _enrich_process(causation.writer_pid, run=run_fn, timeout=timeout)
            correlated = correlated.model_copy(
                update={
                    "process_name": causation.writer_process or correlated.process_name,
                    "command_line": causation.writer_command_line or correlated.command_line,
                    "parent_pid": correlated.parent_pid,
                }
            )
        return ProxyWriterAttributionResult(
            attribution_id=f"pwa-{uuid.uuid4().hex[:12]}",
            timestamp_utc=_now(),
            snapshot=snapshot,
            registry_state=registry_state,
            writer_evidence=writer_rows,
            registry_writer_confirmed=writer_confirmed,
            correlated_process=correlated,
            attribution_confidence=attr_conf,
            confidence_score=confidence,
            classification=classification,
            rationale=rationale,
            limitations=limitations + causation.limitations,
            telemetry_sources=telemetry_sources,
        )

    # No transition window — scan inject_sysmon or classify from snapshot only
    if sysmon_events:
        for ev in sysmon_events:
            if ev.event_id in (12, 13, 14) and is_proxy_registry_target(ev.target_object or ""):
                writer_rows.append(
                    _sysmon_to_writer_evidence(ev, source="sysmon_e13", details_match=False)
                )
        telemetry_sources.append("sysmon_e13")

    writer_confirmed = any(w.event_id == 13 and w.target_object for w in writer_rows)
    details_match = any(w.details_match for w in writer_rows)
    writer_pid = writer_rows[0].pid if writer_rows else None
    attr_conf, confidence = _score_confidence(
        writer_confirmed=writer_confirmed,
        details_match=details_match,
        listener_pid=snapshot.listener.pid,
        writer_pid=writer_pid,
    )

    classification = snapshot.classification.value
    rationale = snapshot.classification_rationale
    if writer_confirmed:
        classification = "REGISTRY_WRITER_CONFIRMED"
        rationale = (
            f"Sysmon registry write observed for {writer_rows[0].value_name or 'proxy value'} "
            f"by {writer_rows[0].process_name or 'unknown'}."
        )
    elif snapshot.classification == ListenerClassification.SUSPICIOUS_PROXY:
        classification = "SUSPICIOUS_PROXY"
    elif "127." in ps.wininet_proxy_server and snapshot.listener.pid is None:
        classification = "UNKNOWN_LOCAL_PROXY"

    correlated = snapshot.listener
    if writer_pid:
        correlated = _enrich_process(writer_pid, run=run_fn, timeout=timeout)

    return ProxyWriterAttributionResult(
        attribution_id=f"pwa-{uuid.uuid4().hex[:12]}",
        timestamp_utc=_now(),
        snapshot=snapshot,
        registry_state=registry_state,
        writer_evidence=writer_rows,
        registry_writer_confirmed=writer_confirmed,
        correlated_process=correlated,
        attribution_confidence=attr_conf,
        confidence_score=confidence,
        classification=classification,
        rationale=rationale,
        limitations=limitations,
        telemetry_sources=telemetry_sources,
    )

"""Read-only proxy attribution collector — never modifies registry or processes."""

from __future__ import annotations

import re
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from src.platform_core.evidence.record import TypedEvidenceRecord

from .classifier import classify_listener
from .models import (
    AttributionSnapshot,
    ListenerClassification,
    ProcessAttribution,
    ProxyStateSnapshot,
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_cmd(argv: list[str], *, run: Callable[..., Any], timeout: float) -> tuple[int, str]:
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
        return int(proc.returncode), ((proc.stdout or "") + (proc.stderr or "")).strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def _localhost_port(proxy_server: str) -> int | None:
    if not proxy_server:
        return None
    if not re.search(r"127(?:\.\d{1,3}){3}|localhost", proxy_server, re.I):
        return None
    m = re.search(r":(\d{1,5})", proxy_server)
    return int(m.group(1)) if m else None


def collect_proxy_state(*, run: Callable[..., Any], timeout: float = 15.0) -> ProxyStateSnapshot:
    """Collect proxy state.

    Args:
        run: run supplied by the caller.
        timeout: timeout supplied by the caller.

    Returns:
        The computed `ProxyStateSnapshot` value.

    Side effects:
        Collects observations from the configured evidence source.
    """
    from windows_network_toolkit.collectors.proxy_registry_collector import collect_proxy_registry

    wininet = collect_proxy_registry(run=run)
    code, winhttp_raw = _run_cmd(["netsh", "winhttp", "show", "proxy"], run=run, timeout=timeout)
    lower = winhttp_raw.lower()
    proxy_server = str(wininet.get("proxy_server") or "")
    return ProxyStateSnapshot(
        wininet_proxy_enable=int(wininet.get("proxy_enable") or 0),
        wininet_proxy_server=proxy_server,
        wininet_proxy_override=str(wininet.get("proxy_override") or ""),
        wininet_auto_config_url=str(wininet.get("auto_config_url") or ""),
        winhttp_raw=winhttp_raw[:800] if code == 0 else "",
        winhttp_direct_access="direct access" in lower and "no proxy server" in lower,
        localhost_port=_localhost_port(proxy_server),
    )


def resolve_listener_process(
    port: int | None,
    *,
    run: Callable[..., Any],
    timeout: float = 20.0,
) -> tuple[ProcessAttribution, bool]:
    """Resolve listener process.

    Args:
        port: port supplied by the caller.
        run: run supplied by the caller.
        timeout: timeout supplied by the caller.

    Returns:
        The computed `tuple[ProcessAttribution, bool]` value.

    Side effects:
        None.
    """
    if port is None:
        return ProcessAttribution(), False
    # Match loopback and wildcard binds (Node/Cursor often listen on 0.0.0.0:port).
    local_needles = (
        f"127.0.0.1:{port}",
        f"0.0.0.0:{port}",
        f"[::]:{port}",
        f"[::1]:{port}",
        f"*:{port}",
    )
    code, out = _run_cmd(["netstat", "-ano"], run=run, timeout=timeout)
    pid: int | None = None
    if code == 0:
        for line in out.splitlines():
            upper = line.upper()
            if "LISTENING" not in upper:
                continue
            if not any(needle in line for needle in local_needles):
                continue
            parts = line.split()
            if parts:
                try:
                    pid = int(parts[-1])
                except ValueError:
                    pid = None
            break
    if pid is None:
        return ProcessAttribution(), False

    proc = ProcessAttribution(pid=pid, process_name="unknown")
    tcode, tout = _run_cmd(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        run=run,
        timeout=10.0,
    )
    if tcode == 0 and tout:
        parts = tout.split(",")
        proc = proc.model_copy(update={"process_name": parts[0].strip('"')})

    ps = (
        f'$p=Get-CimInstance Win32_Process -Filter "ProcessId={pid}";'
        f'$pp=Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue;'
        f"@{{Path=$p.ExecutablePath;Cmd=$p.CommandLine;Start=$p.CreationDate;"
        f"Parent=$p.ParentProcessId;User=$p.GetOwner().User}} | ConvertTo-Json -Compress"
    )
    pcode, pout = _run_cmd(
        ["powershell", "-NoProfile", "-Command", ps],
        run=run,
        timeout=timeout,
    )
    if pcode == 0 and pout.strip().startswith("{"):
        import json

        try:
            row = json.loads(pout)
            proc = proc.model_copy(
                update={
                    "executable_path": str(row.get("Path") or ""),
                    "command_line": str(row.get("Cmd") or ""),
                    "parent_pid": int(row["Parent"]) if row.get("Parent") else None,
                    "start_time_utc": str(row.get("Start") or ""),
                    "user_session": str(row.get("User") or ""),
                }
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return proc, True


def collect_attribution(
    *,
    run: Callable[..., Any] | None = None,
    timeout: float = 15.0,
    inject: dict[str, Any] | None = None,
) -> AttributionSnapshot:
    """Collect read-only proxy attribution snapshot."""
    if inject:
        return AttributionSnapshot.model_validate(inject)

    run_fn = run or subprocess.run
    proxy = collect_proxy_state(run=run_fn, timeout=timeout)
    listener, detected = resolve_listener_process(proxy.localhost_port, run=run_fn, timeout=timeout)
    classification, rationale, limitations = classify_listener(
        proxy, listener, listener_detected=detected
    )
    return AttributionSnapshot(
        snapshot_id=f"attr-{uuid.uuid4().hex[:12]}",
        timestamp_utc=_now(),
        proxy_state=proxy,
        listener=listener,
        classification=classification,
        classification_rationale=rationale,
        limitations=limitations,
    )


def attribution_to_evidence_records(
    snapshot: AttributionSnapshot,
    *,
    event_id: str = "",
) -> list[TypedEvidenceRecord]:
    """Convert attribution snapshot to typed evidence records."""
    eid = event_id or snapshot.snapshot_id
    records: list[TypedEvidenceRecord] = []
    ps = snapshot.proxy_state
    records.append(
        TypedEvidenceRecord.from_observation(
            source="wininet_registry",
            collector="proxy_attribution",
            evidence_type="proxy_enable",
            observed_value=str(ps.wininet_proxy_enable),
            confidence_level="high",
            event_id=eid,
            signal="WININET_PROXY_ENABLE",
        )
    )
    if ps.wininet_proxy_server:
        records.append(
            TypedEvidenceRecord.from_observation(
                source="wininet_registry",
                collector="proxy_attribution",
                evidence_type="proxy_server",
                observed_value=ps.wininet_proxy_server,
                confidence_level="high",
                event_id=eid,
                signal="WININET_PROXY_SERVER",
            )
        )
    if snapshot.listener.pid:
        records.append(
            TypedEvidenceRecord.from_observation(
                source="netstat_owner",
                collector="proxy_attribution",
                evidence_type="listener_owner",
                observed_value=f"{snapshot.listener.process_name}:{snapshot.listener.pid}",
                confidence_level="medium",
                evidence_tier="CORRELATED",
                limitations=snapshot.limitations,
                event_id=eid,
                signal="LISTENER_OWNER",
            )
        )
    records.append(
        TypedEvidenceRecord.from_observation(
            source="attribution_classifier",
            collector="proxy_attribution",
            evidence_type="listener_classification",
            observed_value=snapshot.classification.value,
            confidence_level="medium",
            evidence_tier="CORRELATED"
            if snapshot.classification != ListenerClassification.NO_PROXY
            else "OBSERVED_ONLY",
            limitations=snapshot.limitations,
            raw_reference=snapshot.classification_rationale,
            event_id=eid,
            signal="LISTENER_CLASSIFICATION",
        )
    )
    return records

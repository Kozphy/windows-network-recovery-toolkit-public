"""Post-login proxy boot trace with delta detection."""

from __future__ import annotations

import socket
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.logging.audit import append_jsonl
from src.proxy_drift.classify import classify_proxy_drift
from src.proxy_guard.listener_attribution import attribute_localhost_proxy_listener
from src.proxy_guard.parser import parse_proxy_server
from src.proxy_guard.registry import read_proxy_registry

_SCHEMA = "proxy_boot_trace.v1"


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _winhttp_direct(run: Callable[..., Any]) -> bool | None:
    try:
        proc = run(
            ["netsh", "winhttp", "show", "proxy"],
            capture_output=True,
            text=True,
            timeout=20,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or "").lower()
    return "direct access" in text


def _port_listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.35):
            return True
    except OSError:
        return False


def _snapshot(run: Callable[..., Any]) -> dict[str, Any]:
    reg = read_proxy_registry(run=run)
    parsed = parse_proxy_server(reg.proxy_server)
    listener_found: bool | None = None
    listener: dict[str, Any] = {}
    if parsed.is_localhost_proxy and parsed.localhost_port:
        listener_found = _port_listening(int(parsed.localhost_port))
        attr = attribute_localhost_proxy_listener(reg.proxy_server, run=run)
        actor = attr.candidate_actor
        if actor is not None:
            listener = {
                "pid": actor.pid,
                "process_name": actor.process_name,
                "exe_path": actor.image_path,
                "command_line": actor.command_line,
                "parent_pid": actor.parent_pid,
                "parent_process_name": actor.parent_process_name,
            }
    classification = classify_proxy_drift(
        proxy_enable=reg.proxy_enable,
        proxy_server=reg.proxy_server,
        auto_config_url=reg.auto_config_url,
        winhttp_direct=_winhttp_direct(run),
        listener_found=listener_found,
        process_name=listener.get("process_name"),
        command_line=listener.get("command_line"),
    )
    return {
        "timestamp_utc": _now(),
        "wininet": {
            "proxy_enable": reg.proxy_enable,
            "proxy_server": reg.proxy_server,
            "auto_config_url": reg.auto_config_url,
            "proxy_override": reg.proxy_override,
        },
        "winhttp_direct": _winhttp_direct(run),
        "listener_found": listener_found,
        "listener": listener,
        "classification": classification,
    }


def _deltas(prev: dict[str, Any] | None, cur: dict[str, Any]) -> list[str]:
    if prev is None:
        return ["initial_sample"]
    events: list[str] = []
    pw = prev.get("wininet") or {}
    cw = cur.get("wininet") or {}
    if pw.get("proxy_enable") != cw.get("proxy_enable"):
        events.append("proxy_enable_changed")
    if pw.get("proxy_server") != cw.get("proxy_server"):
        events.append("proxy_server_changed")
    if prev.get("listener_found") is False and cur.get("listener_found") is True:
        events.append("listener_appeared")
    if prev.get("listener_found") is True and cur.get("listener_found") is False:
        events.append("listener_exited")
    cls = str((cur.get("classification") or {}).get("classification") or "")
    if cls in {"STALE_LOCALHOST_PROXY", "STALE_PROXY_AFTER_PROCESS_EXIT"}:
        events.append("dead_localhost_proxy_observed")
    return events


def run_boot_trace_loop(
    *,
    duration_seconds: float = 180.0,
    interval_seconds: float = 2.0,
    audit_path: Path | None = None,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Poll proxy state for a bounded window and append JSONL audit rows."""
    from pathlib import Path

    subprocess_run = run if run is not None else subprocess.run
    log_path = audit_path or Path("logs") / "proxy_boot_trace.jsonl"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    end = time.monotonic() + max(1.0, duration_seconds)
    interval = max(0.5, interval_seconds)
    samples: list[dict[str, Any]] = []
    prev: dict[str, Any] | None = None
    while time.monotonic() < end:
        snap = _snapshot(subprocess_run)
        delta = _deltas(prev, snap)
        row = {"schema_version": _SCHEMA, "event": "boot_trace_sample", "delta_events": delta, **snap}
        samples.append(row)
        append_jsonl(log_path, row)
        prev = snap
        if time.monotonic() >= end:
            break
        time.sleep(interval)

    return {
        "schema_version": _SCHEMA,
        "samples_collected": len(samples),
        "audit_path": str(log_path.resolve()),
        "limitations": [
            "Boot trace records observations — not registry writer proof.",
            "Classification is not accusation.",
        ],
    }

"""Proxy watch facade — read-only drift polling with health and reverter diagnosis.

Module responsibility:
    Poll WinINET proxy state on an interval, detect changes, run health probes on transitions,
    append audit rows to ``proxy-watch.jsonl``, and surface reverter/flapping diagnosis.

System placement:
    Backing implementation for ``cli proxy-watch`` and intermittent check scripts.

Key invariants:
    * Read-only on registry — no auto-disable or process kill.
    * Change events include health_audit and classification when probes succeed.
    * Timestamps UTC ISO-8601.

Side effects:
    Appends to ``proxy-watch.jsonl`` via ``append_audit_dict``; network probes on transitions.

Audit Notes:
    * Reverter diagnosis is correlation-only unless T4 writer proof collected separately.
"""

from __future__ import annotations

import platform
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from src.proxy_guard.parser import parse_proxy_server
from windows_network_toolkit.audit_store import append_audit_dict
from windows_network_toolkit.proxy_health import (
    ProxyHealthResult,
    build_proxy_health_audit_payload,
    check_localhost_proxy_health,
    classify_incident_from_health,
)
from windows_network_toolkit.proxy_owner import detect_proxy_owner
from windows_network_toolkit.proxy_state import collect_proxy_state_model
from windows_network_toolkit.proxy_state_machine import (
    CoalescingBuffer,
    TransitionClass,
    build_proxy_evidence_event,
    detect_reverter_loop_pattern,
)
from windows_network_toolkit.proxy_watch_diagnosis import analyze_proxy_watch_history


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_key(state: dict[str, Any]) -> str:
    return (
        f"{state.get('wininet_proxy_enabled')}:"
        f"{state.get('wininet_proxy_server')}:"
        f"{state.get('wininet_auto_config_url')}"
    )


def _is_localhost_transition(state: dict[str, Any]) -> bool:
    if not state.get("wininet_proxy_enabled"):
        return False
    parsed = parse_proxy_server(state.get("wininet_proxy_server"))
    return bool(parsed.is_localhost_proxy and parsed.localhost_port)


def _risk_label(classification: dict[str, Any]) -> str:
    return str(classification.get("risk") or "MEDIUM").upper()


def format_proxy_change_human(change: dict[str, Any]) -> str:
    """Format a proxy change record for terminal or log output.

    Args:
        change: Proxy change dict with old/new state, optional ``transition_evidence``,
            ``health_audit``, and ``reverter_diagnosis``.

    Returns:
        Multi-line human-readable summary including limitations and correlation disclaimers.

    Side effects:
        None.
    """
    old = change.get("old_state") or change.get("before") or change.get("before_state") or {}
    new = change.get("new_state") or change.get("after") or change.get("after_state") or {}
    evidence = change.get("transition_evidence") or change.get("audit_evidence") or {}
    lines = [
        "[PROXY CHANGE DETECTED]",
        "ProxyServer changed:",
        f"  before: {old.get('wininet_proxy_server') or old.get('proxy_server') or 'None'}",
        f"  after: {new.get('wininet_proxy_server') or new.get('proxy_server') or 'None'}",
        f"ProxyEnable: {int(bool(old.get('wininet_proxy_enabled') if 'wininet_proxy_enabled' in old else old.get('proxy_enable')))} -> "
        f"{int(bool(new.get('wininet_proxy_enabled') if 'wininet_proxy_enabled' in new else new.get('proxy_enable')))}",
        "",
    ]
    if evidence:
        lines.append(f"Transition: {evidence.get('transition_class', 'UNKNOWN')}")
        lines.append(f"Risk: {evidence.get('risk', 'MEDIUM')}")
        lines.append(f"Proof tier: {evidence.get('proof_tier', 'T1')}")
        lines.append(f"Recommended action: {evidence.get('recommended_action', '')}")
        for lim in evidence.get("limitations") or []:
            lines.append(f"  Limitation: {lim}")
        lines.append("")
    audit = change.get("health_audit") or {}
    classification = audit.get("classification") or change.get("classification") or {}
    if not evidence:
        lines.append(f"Risk: {_risk_label(classification)}")
        lines.append("")

    health = audit.get("health") or {}
    if health:
        lines.append("Proxy health:")
        lines.append(f"  Status: {health.get('proxy_status', 'INSUFFICIENT_DATA')}")
        lines.append(f"  TCP listener: {'yes' if health.get('tcp_listening') else 'no'}")
        if health.get("listener_name"):
            lines.append(
                f"  Listener process: {health.get('listener_name')} PID {health.get('listener_pid')}"
            )
        lines.append(
            f"  Proxy HTTPS probe: {'ok' if health.get('proxy_probe_ok') or health.get('proxy_https_connect_ok') else 'failed'}"
        )
        lines.append(
            f"  Direct HTTPS probe: {'ok' if health.get('direct_probe_ok') else 'failed'}"
        )
        interp = classification.get("human_interpretation")
        if interp:
            lines.append(f"  Interpretation: {interp}")
        lines.append("")

    reverter = change.get("reverter_diagnosis") or audit.get("reverter_diagnosis") or {}
    if reverter.get("status") and reverter.get("status") != "NONE":
        lines.append(f"Reverter diagnosis: {reverter.get('status')} (confidence {reverter.get('confidence', 0):.2f})")
        lines.append("")

    lines.append("Evidence:")
    for item in audit.get("evidence") or change.get("evidence") or []:
        lines.append(f"- {item}")

    policy = classification.get("recommended_policy_action")
    if policy:
        lines.append("")
        lines.append(f"Recommended policy action: {policy}")

    owner = change.get("owner") or {}
    proc = owner.get("process") if isinstance(owner.get("process"), dict) else None
    if proc and proc.get("name"):
        lines.append("")
        lines.append(
            f"Likely process / correlation only: {proc.get('name')} (PID {proc.get('pid')}) — "
            "registry writer proof unavailable"
        )

    return "\n".join(lines)


def run_proxy_watch(
    *,
    duration: int = 900,
    interval: float = 2.0,
    coalesce_ms: int = 1000,
    inject_sequence: list[dict[str, Any]] | None = None,
    run: Any = None,
    health_check_fn: Callable[..., ProxyHealthResult] | None = None,
    health_inject: dict[str, Any] | None = None,
    run_direct_probe: bool = True,
    run_proxy_probe: bool = True,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Poll WinINET proxy state and append drift events to audit JSONL.

    Args:
        duration: Watch duration in seconds (live Windows mode).
        interval: Poll interval in seconds.
        coalesce_ms: Merge rapid sub-changes within this window (200–5000 ms).
        inject_sequence: Fixture state sequence for offline/tests (skips Windows check).
        run: Injectable ``subprocess.run`` for tests.
        health_check_fn: Injectable localhost health checker.
        health_inject: Fixture overrides for health probes.
        run_direct_probe: Whether to run direct HTTPS probe on localhost transitions.
        run_proxy_probe: Whether to run proxied HTTPS probe.
        timeout_seconds: Probe timeout.

    Returns:
        Summary dict with ``polls``, ``events``, ``change_count``, ``reverter_diagnosis``,
        and ``transition_evidence``. Returns ``unsupported_platform`` on non-Windows without
        ``inject_sequence``.

    Side effects:
        Appends rows to ``.audit/proxy-watch.jsonl`` via ``append_audit_dict``.
        Runs TCP/HTTPS probes on localhost proxy transitions.

    Audit Notes:
        Does not mutate registry or kill processes. Reverter flags require human review.
        Correlation-only process names must not be narrated as registry writers.
    """
    if platform.system() != "Windows" and inject_sequence is None:
        return {
            "unsupported_platform": True,
            "platform": platform.system(),
            "message": "proxy-watch requires Windows or inject_sequence fixture.",
        }

    run_fn = run or subprocess.run
    coalesce_ms = max(200, min(int(coalesce_ms), 5000))
    events: list[dict[str, Any]] = []
    change_events: list[dict[str, Any]] = []
    transition_evidence_log: list[dict[str, Any]] = []
    prior: dict[str, Any] | None = None
    start = time.monotonic()
    polls = 0
    health_fn = health_check_fn or check_localhost_proxy_health
    coalesce_buffer = CoalescingBuffer(coalesce_window_ms=coalesce_ms)

    def _apply_transition_evidence(
        event: dict[str, Any],
        old_state: dict[str, Any],
        new_state: dict[str, Any],
        *,
        owner: dict[str, Any] | None,
        coalesce_meta: dict[str, Any] | None = None,
        raw_sub_events: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        winhttp_mismatch = bool(new_state.get("wininet_proxy_enabled") and new_state.get("winhttp_direct_access"))
        evidence = build_proxy_evidence_event(
            before_raw=old_state,
            after_raw=new_state,
            timestamp_utc=str(event.get("timestamp_utc") or _now()),
            listener=owner,
            winhttp_mismatch=winhttp_mismatch,
            coalesce_meta=coalesce_meta,
            raw_sub_events=raw_sub_events,
        )
        loop = detect_reverter_loop_pattern(transition_evidence_log + [evidence])
        if loop == TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP:
            evidence["transition_class"] = str(loop)
            evidence["risk"] = "HIGH"
            evidence["recommended_action"] = (
                "require human review — pattern suggests a proxy reverter or auto-reapply loop; "
                "this is correlation, not proof of registry write"
            )
            evidence["limitations"] = [
                "Pattern suggests a proxy reverter or auto-reapply loop",
                "This is correlation, not proof of registry write",
                "Collect Sysmon Event ID 13 or Procmon trace for registry writer proof",
                "Investigate listener process executable path and command line",
            ]
            evidence["policy_decision"] = "REQUIRE_HUMAN_REVIEW"
            event["reverter_suspected"] = True
            event["classification_hint"] = str(loop)
        event["transition_evidence"] = evidence
        event["audit_evidence"] = evidence
        transition_evidence_log.append(evidence)
        return evidence

    def _enrich_change(
        event: dict[str, Any],
        old_state: dict[str, Any],
        new_state: dict[str, Any],
    ) -> None:
        owner: dict[str, Any] | None = None
        health: ProxyHealthResult | None = None
        audit: dict[str, Any] | None = None

        if _is_localhost_transition(new_state):
            owner = detect_proxy_owner(inject_state=new_state, run=run_fn)
            parsed = parse_proxy_server(new_state.get("wininet_proxy_server"))
            host = parsed.localhost_host or "127.0.0.1"
            port = int(parsed.localhost_port or new_state.get("localhost_port") or 0)
            health = health_fn(
                host,
                port,
                listener_info=owner,
                inject=health_inject,
                run_direct_probe=run_direct_probe,
                run_proxy_probe=run_proxy_probe,
                timeout_seconds=timeout_seconds,
            )
            reverter_flag = bool(event.get("reverter_suspected"))
            classification = classify_incident_from_health(
                health,
                wininet_enabled=True,
                reverter_suspected=reverter_flag,
                winhttp_mismatch=bool(
                    new_state.get("wininet_proxy_enabled") and new_state.get("winhttp_direct_access")
                ),
            )
            audit = build_proxy_health_audit_payload(
                wininet=new_state,
                health=health,
                classification=classification,
                extra_evidence=[
                    f"WinINET ProxyServer parses to localhost port {port}",
                ],
            )
            event["owner"] = owner
            event["health"] = health.to_dict()
            event["health_audit"] = audit
            event["classification"] = classification

        reverter = analyze_proxy_watch_history(change_events + [event])
        event["reverter_diagnosis"] = reverter.to_dict()
        if audit:
            audit["reverter_diagnosis"] = reverter.to_dict()
        if reverter.status == "REVERTER_SUSPECTED":
            event["reverter_suspected"] = True
            event["classification_hint"] = "REVERTER_SUSPECTED"
            event["confidence"] = reverter.confidence

        change_record = {
            "timestamp_utc": event.get("timestamp_utc"),
            "before": old_state,
            "after": new_state,
            "owner": owner,
            "health": health.to_dict() if health else None,
        }
        change_events.append(change_record)

    def _finalize_coalesced(merged: dict[str, Any]) -> None:
        before = merged.get("before") or merged.get("before_state") or {}
        after = merged.get("after") or merged.get("after_state") or {}
        event: dict[str, Any] = {
            "timestamp_utc": merged.get("timestamp_utc") or _now(),
            "event": "proxy_change",
            "old_state": before,
            "new_state": after,
            "coalesced": merged.get("coalesced", False),
            "coalesce_window_ms": merged.get("coalesce_window_ms", coalesce_ms),
            "raw_sub_event_count": merged.get("raw_sub_event_count", 1),
        }
        if merged.get("raw_sub_events"):
            event["raw_sub_events"] = merged["raw_sub_events"]
        _enrich_change(event, before, after)
        _apply_transition_evidence(
            event,
            before,
            after,
            owner=event.get("owner"),
            coalesce_meta={
                "coalesced": event.get("coalesced", False),
                "coalesce_window_ms": event.get("coalesce_window_ms", coalesce_ms),
                "raw_sub_event_count": event.get("raw_sub_event_count", 1),
            },
            raw_sub_events=event.get("raw_sub_events"),
        )
        if event.get("transition_evidence"):
            te = event["transition_evidence"]
            if audit := event.get("health_audit"):
                audit["transition_evidence"] = te
            append_audit_dict(event, log_name="proxy-watch.jsonl")
        events.append(event)

    def _poll(inject: dict[str, Any] | None = None) -> dict[str, Any]:
        nonlocal prior, polls
        state = collect_proxy_state_model(run=run_fn, inject=inject).to_dict()
        polls += 1
        event: dict[str, Any] = {
            "timestamp_utc": _now(),
            "event": "poll",
            "state": state,
        }
        if prior is not None and _state_key(prior) != _state_key(state):
            elapsed = round(time.monotonic() - start, 1)
            raw_change = {
                "timestamp_utc": event["timestamp_utc"],
                "event": "proxy_change",
                "old_state": prior,
                "new_state": state,
                "before": prior,
                "after": state,
                "elapsed_seconds": elapsed,
            }
            for flushed in coalesce_buffer.add(raw_change):
                _finalize_coalesced(flushed)
        elif prior is None:
            event["event"] = "initial_poll"
            append_audit_dict(event, log_name="proxy-watch.jsonl")
        events.append(event)
        prior = state
        return event

    if inject_sequence is not None:
        for row in inject_sequence:
            _poll(inject=row)
        for flushed in coalesce_buffer.flush():
            _finalize_coalesced(flushed)
        summary_reverter = analyze_proxy_watch_history(change_events)
        return {
            "polls": polls,
            "events": events,
            "duration_seconds": 0,
            "change_count": len([e for e in events if e.get("event") == "proxy_change"]),
            "coalesce_window_ms": coalesce_ms,
            "reverter_diagnosis": summary_reverter.to_dict(),
            "transition_evidence": transition_evidence_log,
        }

    deadline = time.monotonic() + duration
    first = _poll()
    while time.monotonic() < deadline:
        time.sleep(interval)
        _poll()
    for flushed in coalesce_buffer.flush():
        _finalize_coalesced(flushed)

    summary_reverter = analyze_proxy_watch_history(change_events)
    return {
        "polls": polls,
        "events": events,
        "duration_seconds": duration,
        "initial_poll": first,
        "change_count": len([e for e in events if e.get("event") == "proxy_change"]),
        "coalesce_window_ms": coalesce_ms,
        "reverter_diagnosis": summary_reverter.to_dict(),
        "transition_evidence": transition_evidence_log,
    }

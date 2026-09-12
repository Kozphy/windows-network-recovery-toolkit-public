"""Latest endpoint evidence report — proxy state, health, timeline, control tests.

Module responsibility:
    Assemble a point-in-time evidence package for ``evidence-report --latest`` by combining
    live or injected proxy state, health probes, timeline, reverter diagnosis, control tests,
    and a dry-run remediation preview.

System placement:
    Operator-facing report path parallel to ``analytics_pipeline`` (batch analytics over
    audit JSONL). Uses ``proxy_state``, ``proxy_health``, ``proxy_owner``, ``control_tests``,
    and ``proxy_remediation`` (preview only).

Key invariants:
    * ``safe_remediation_preview`` always uses ``run_proxy_disable(dry_run=True)``.
    * Timestamps use UTC via ``datetime.now(UTC)`` formatted as ``%Y-%m-%dT%H:%M:%SZ``.
    * Schema version: ``endpoint_evidence_latest.v1``.

Side effects:
    Read-only except when not using inject fixtures (reads ``.audit/proxy-watch.jsonl``).
    Remediation preview does not mutate registry when dry_run=True.

Audit Notes:
    * Live collection on Windows reads registry/netstat — document operator context in audit.
    * Recovery: use ``--fixture`` inject paths for reproducible portfolio reports.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from windows_network_toolkit.audit_store import read_audit_logs
from windows_network_toolkit.control_tests import control_tests_to_dict, run_endpoint_control_tests
from windows_network_toolkit.proxy_health import run_proxy_health_for_state
from windows_network_toolkit.proxy_owner import detect_proxy_owner
from windows_network_toolkit.proxy_remediation import run_proxy_disable
from windows_network_toolkit.proxy_state import collect_proxy_state_model
from windows_network_toolkit.proxy_watch_diagnosis import analyze_proxy_watch_history


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timeline_from_audit_or_fixture(
    *,
    fixture_timeline: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if fixture_timeline is not None:
        return fixture_timeline
    rows = read_audit_logs(pattern="proxy-watch.jsonl")
    timeline: list[dict[str, Any]] = []
    for row in rows:
        if row.get("event") == "proxy_change":
            timeline.append({
                "timestamp_utc": row.get("timestamp_utc"),
                "old_state": row.get("old_state"),
                "new_state": row.get("new_state"),
                "health": row.get("health"),
                "reverter_diagnosis": row.get("reverter_diagnosis"),
            })
        elif row.get("event") in ("poll", "initial_poll"):
            timeline.append({
                "timestamp_utc": row.get("timestamp_utc"),
                "event": row.get("event"),
                "state": row.get("state"),
            })
    return timeline


def _change_records_for_reverter(timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in timeline:
        if item.get("new_state"):
            records.append({
                "before": item.get("old_state"),
                "after": item.get("new_state"),
                "owner": item.get("owner"),
                "health": item.get("health"),
            })
        elif item.get("event") == "proxy_change":
            records.append(item)
    return records


def build_latest_evidence_package(
    *,
    inject_state: dict[str, Any] | None = None,
    inject_owner: dict[str, Any] | None = None,
    inject_health: dict[str, Any] | None = None,
    inject_timeline: list[dict[str, Any]] | None = None,
    inject_reverter: dict[str, Any] | None = None,
    health_kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble JSON package for latest evidence report.

    Args:
        inject_*: Optional fixtures for offline/portfolio runs; omit for live Windows collection.
        health_kwargs: Forwarded to ``run_proxy_health_for_state`` (e.g. inject probe results).

    Returns:
        Dict with schema_version ``endpoint_evidence_latest.v1``, incident summary, state,
        health, timeline, control tests, limitations, and dry-run remediation preview.

    Side effects:
        May read audit JSONL and query registry/network when inject args are None.
        Calls ``run_proxy_disable(dry_run=True)`` for preview only.

    Audit Notes:
        Preview block must not be executed without typed confirmation on live hosts.
    """
    state = collect_proxy_state_model(inject=inject_state).to_dict()
    owner = detect_proxy_owner(inject=inject_owner, inject_state=inject_state)
    hk = dict(health_kwargs or {})
    if inject_health:
        hk["inject"] = inject_health
    health_audit = run_proxy_health_for_state(state, owner, **hk)
    timeline = _timeline_from_audit_or_fixture(fixture_timeline=inject_timeline)
    reverter = inject_reverter
    if reverter is None:
        reverter = analyze_proxy_watch_history(_change_records_for_reverter(timeline)).to_dict()
    controls = run_endpoint_control_tests(
        proxy_state=state,
        health_audit=health_audit,
        owner=owner,
        reverter_diagnosis=reverter,
        timeline=timeline,
    )
    remediation_preview = run_proxy_disable(dry_run=True, confirm="")
    classification = health_audit.get("classification") or {}
    return {
        "schema_version": "endpoint_evidence_latest.v1",
        "generated_at_utc": _now(),
        "incident_summary": {
            "headline": classification.get("incident_class", "ENDPOINT_PROXY_REVIEW"),
            "risk": classification.get("risk"),
            "proxy_status": (health_audit.get("health") or {}).get("proxy_status"),
            "interpretation": classification.get("human_interpretation"),
        },
        "proxy_state": state,
        "proxy_owner": owner,
        "health_audit": health_audit,
        "timeline": timeline,
        "reverter_diagnosis": reverter,
        "control_tests": control_tests_to_dict(controls),
        "limitations": list(health_audit.get("limitations") or []) + list(reverter.get("limitations") or []),
        "recommended_next_proof": [
            "Enable Sysmon Event ID 13 for registry writer proof",
            "Run proxy-watch --format human during reproduction",
            "Collect Procmon registry trace if reverter suspected",
        ],
        "safe_remediation_preview": remediation_preview,
    }


def render_latest_evidence_markdown(package: dict[str, Any]) -> str:
    """Render operator and auditor markdown from a latest evidence package.

    Args:
        package: Output of ``build_latest_evidence_package``.

    Returns:
        Markdown string suitable for stdout or file export.

    Side effects:
        None.
    """
    summary = package.get("incident_summary") or {}
    state = package.get("proxy_state") or {}
    health = (package.get("health_audit") or {}).get("health") or {}
    owner = package.get("proxy_owner") or {}
    proc = owner.get("process") if isinstance(owner.get("process"), dict) else None
    lines = [
        "# Endpoint network evidence report (latest)",
        "",
        f"Generated: {package.get('generated_at_utc')}",
        "",
        "## Incident summary",
        "",
        f"- **Headline:** {summary.get('headline')}",
        f"- **Risk:** {summary.get('risk')}",
        f"- **Proxy health status:** {summary.get('proxy_status')}",
        f"- **Interpretation:** {summary.get('interpretation')}",
        "",
        "## Current WinINET / WinHTTP state",
        "",
        f"- ProxyEnable: `{int(bool(state.get('wininet_proxy_enabled')))}`",
        f"- ProxyServer: `{state.get('wininet_proxy_server') or ''}`",
        f"- AutoConfigURL: `{state.get('wininet_auto_config_url') or ''}`",
        f"- WinHTTP direct access: `{state.get('winhttp_direct_access')}`",
        "",
        "## Proxy health",
        "",
        f"- Status: `{health.get('proxy_status')}`",
        f"- TCP listener: `{health.get('tcp_listening')}`",
        f"- Proxy HTTPS probe: `{'ok' if health.get('proxy_probe_ok') else 'failed'}`",
        f"- Direct HTTPS probe: `{'ok' if health.get('direct_probe_ok') else 'failed'}`",
    ]
    if proc:
        lines.append(f"- Likely listener (correlation only): `{proc.get('name')}` PID `{proc.get('pid')}`")
    lines.extend(["", "## Direct vs proxy path comparison", ""])
    lines.append(f"- Direct path: **{'OK' if health.get('direct_probe_ok') else 'FAIL'}**")
    lines.append(f"- Proxy path: **{'OK' if health.get('proxy_probe_ok') else 'FAIL'}**")
    rev = package.get("reverter_diagnosis") or {}
    if rev.get("status") and rev.get("status") != "NONE":
        lines.extend([
            "",
            "## Reverter / timeline diagnosis",
            "",
            f"- Status: `{rev.get('status')}` (confidence {rev.get('confidence', 0):.2f})",
            f"- Enable/disable cycles: `{rev.get('enable_disable_cycle_count')}`",
            f"- Last ports: `{rev.get('last_ports')}`",
        ])
        if rev.get("suspected_reverter_process"):
            lines.append(f"- Suspected process (correlation): `{rev.get('suspected_reverter_process')}`")
    lines.extend(["", "## Timeline", ""])
    timeline = package.get("timeline") or []
    if not timeline:
        lines.append("_No proxy-watch timeline rows in `.audit/proxy-watch.jsonl` — run proxy-watch to populate._")
    else:
        for i, item in enumerate(timeline[-10:], 1):
            ts = item.get("timestamp_utc", "?")
            if item.get("new_state"):
                old_s = (item.get("old_state") or {}).get("wininet_proxy_server")
                new_s = (item.get("new_state") or {}).get("wininet_proxy_server")
                lines.append(f"{i}. `{ts}` ProxyServer `{old_s}` → `{new_s}`")
            else:
                lines.append(f"{i}. `{ts}` {item.get('event', 'event')}")
    lines.extend(["", "## Control test results", ""])
    for ctrl in package.get("control_tests") or []:
        lines.append(f"### {ctrl.get('control_id')} — **{ctrl.get('test_result')}**")
        lines.append(f"- Objective: {ctrl.get('control_objective')}")
        lines.append(f"- Risk: {ctrl.get('risk')}")
        for ev in ctrl.get("evidence") or []:
            lines.append(f"  - {ev}")
        if ctrl.get("recommendation"):
            lines.append(f"- Recommendation: {ctrl.get('recommendation')}")
        lines.append("")
    lines.extend(["## Limitations", ""])
    for lim in package.get("limitations") or []:
        lines.append(f"- {lim}")
    lines.extend(["", "## Recommended next proof step", ""])
    for step in package.get("recommended_next_proof") or []:
        lines.append(f"- {step}")
    preview = package.get("safe_remediation_preview") or {}
    lines.extend([
        "",
        "## Safe remediation preview",
        "",
        f"- Action allowed: `{preview.get('action_allowed')}`",
        f"- Dry run: `{preview.get('dry_run', True)}`",
        f"- Note: `{preview.get('message') or preview.get('preview_note') or 'Preview only — typed confirmation required for live apply.'}`",
    ])
    return "\n".join(lines)

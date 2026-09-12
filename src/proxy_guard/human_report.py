"""Human-readable formatters for proxy guard watch / change audit JSONL rows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .causality_labels import (
    REGISTRY_WRITER_PROOF,
    attribution_mode_label,
    format_cpu_process_snapshot,
    format_listener_correlation,
    process_candidate_wording,
)
from .flip_flop import ActiveReverterResult, detect_active_reverter, normalize_watch_record
from .operator_language import display_policy_decision, policy_decision_note


def load_watch_jsonl(path: Path, *, tail_n: int = 10) -> list[dict[str, Any]]:
    """Load JSON objects from watch JSONL; normalize legacy v1 rows on read."""

    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(normalize_watch_record(obj))
    if tail_n < 1:
        return rows
    return rows[-tail_n:]


def format_active_reverter_incident(incident: ActiveReverterResult) -> str:
    """Incident block for repeated ProxyEnable toggles."""

    d = incident.to_dict()
    lines = [
        "!" * 72,
        f"INCIDENT: {incident.incident_class}",
        "!" * 72,
        d["summary"],
        f"Toggles in last {incident.window_minutes}m: {incident.toggle_count}",
        f"Window: {incident.first_seen_utc} -> {incident.last_seen_utc}",
        "",
        "RECOMMENDED (do not loop reset_proxy):",
    ]
    for step in d["recommended_actions"]:
        lines.append(f"  - {step}")
    lines.append("!" * 72)
    return "\n".join(lines)


def _proxy_on_label(value: Any) -> str:
    if value is None:
        return "unknown"
    try:
        return "ON" if int(value) == 1 else "OFF"
    except (TypeError, ValueError):
        return str(value)


def _headline_for_transition(before: dict[str, Any], after: dict[str, Any]) -> str:
    be = before.get("proxy_enable")
    ae = after.get("proxy_enable")
    bs = before.get("proxy_server")
    asrv = after.get("proxy_server")
    if be == 0 and ae == 1:
        return "Proxy turned ON -- browser/app traffic may be redirected (not judged safe)"
    if be == 1 and ae == 0:
        return "Proxy turned OFF -- direct access if nothing re-enables it"
    if bs != asrv:
        return "Proxy server address changed"
    return "Proxy settings changed"


def _recommended_steps(record: dict[str, Any]) -> list[str]:
    before = record.get("before_snapshot") or {}
    after = record.get("after_snapshot") or {}
    ae = after.get("proxy_enable")
    server = after.get("proxy_server") or before.get("proxy_server")
    steps: list[str] = []
    proc = (record.get("attribution") or {}).get("process") or {}
    pname = proc.get("name")
    pid = proc.get("pid")

    if ae == 1:
        steps.append(
            "Run scripts\\reset_proxy.bat as Administrator OR "
            "python -m src proxy-disable --dry-run false --confirm DISABLE_WININET_PROXY "
            "(clears ProxyEnable, ProxyServer, AutoConfigURL by default)."
        )
        if pname and pid is not None:
            steps.append(
                f"Investigate {process_candidate_wording(str(pname))} PID {pid} — stop process tree before repeating resets."
            )
        if server and "127.0.0.1" in str(server).lower():
            steps.append("Localhost proxy observed — close dev/desktop apps that may re-enable system proxy.")
        steps.append("Verify: python -m src proxy-status")
    elif ae == 0:
        steps.append("If browsing works, run soak: proxy-disable ... --soak-minutes 15")
        if after.get("proxy_server"):
            steps.append("LATENT_MISCONFIG: ProxyServer still set — full clear required.")
    else:
        steps.append("Review reports\\proxy_guard_watch.jsonl (canonical) for correlated events.")

    steps.append("Human-readable tail: python -m src proxy-watch-report --tail 5")
    return steps


def format_proxy_guard_change(record: dict[str, Any]) -> str:
    """Format one schema v2 ``proxy_guard_change`` (or compatible) audit row."""

    record = normalize_watch_record(record)
    event = str(record.get("event") or "proxy_guard_change")
    ts = record.get("timestamp") or record.get("timestamp_utc") or "unknown"
    before = record.get("before_snapshot") or {}
    after = record.get("after_snapshot") or {}
    attrib = record.get("attribution") or {}
    policy = record.get("policy_decision") or {}
    rollback = record.get("rollback_result") or {}
    proc = attrib.get("process") or {}
    raw_decision = policy.get("decision")
    op_decision = display_policy_decision(raw_decision, reason=str(policy.get("reason") or ""))
    path_ops = policy.get("proxy_path_operational") or {}

    lines = [
        "=" * 72,
        "PROXY GUARD - CHANGE EVENT (schema v2)",
        "=" * 72,
        f"Time (UTC):  {ts}",
        f"Event:       {event}",
        f"Summary:     {_headline_for_transition(before, after)}",
        "",
        "WININET (HKCU) -- before -> after",
        f"  ProxyEnable:  {_proxy_on_label(before.get('proxy_enable'))}  ->  {_proxy_on_label(after.get('proxy_enable'))}",
        f"  ProxyServer:  {before.get('proxy_server') or '(none)'}  ->  {after.get('proxy_server') or '(none)'}",
    ]
    pac_b = before.get("auto_config_url")
    pac_a = after.get("auto_config_url")
    if pac_b or pac_a:
        lines.append(f"  AutoConfigURL:  {pac_b or '(none)'}  ->  {pac_a or '(none)'}")

    kind = attribution_mode_label(attrib.get("mode"))
    lines.append("")
    if kind == REGISTRY_WRITER_PROOF:
        lines.append(f"Evidence kind: {REGISTRY_WRITER_PROOF}")
        lines.append("Registry writer telemetry correlated (see limitations).")
    else:
        lines.extend(
            format_listener_correlation(
                process_name=proc.get("name"),
                pid=proc.get("pid"),
                ppid=proc.get("ppid"),
                exe=proc.get("exe"),
            )
        )

    lines.extend(
        [
            "",
            "CONTAINMENT POLICY (operator view)",
            f"  Stored decision:     {raw_decision}",
            f"  Operator decision:   {op_decision}",
            f"  Note:                {policy_decision_note(op_decision)}",
            f"  Reason:              {policy.get('reason') or 'unknown'}",
        ]
    )
    if policy.get("matched_rule"):
        lines.append(f"  Matched rule:        {policy.get('matched_rule')}")

    if path_ops:
        lines.extend(
            [
                "",
                "PROXY PATH OPERATIONAL (registry vs browser path)",
                f"  Composite state:     {path_ops.get('composite_state') or 'unknown'}",
                f"  Evidence tier:       {path_ops.get('evidence_tier') or 'unknown'}",
                f"  Policy hint:         {path_ops.get('policy_recommendation') or 'unknown'}",
                f"  Summary:             {path_ops.get('human_summary') or ''}",
            ]
        )
        operational = path_ops.get("operational") or {}
        if operational:
            lines.append(
                "  Signals:             "
                f"listener_up={operational.get('listener_up')}; "
                f"proxied_https_ok={operational.get('proxied_https_ok')}; "
                f"bypass_https_ok={operational.get('bypass_https_ok')}; "
                f"browser_path_healthy={operational.get('browser_path_healthy')}"
            )
        lines.append(
            "  Note:                ProxyEnable=1 alone does not prove browser failure; "
            "contrast checks separate operational from broken loopback paths."
        )

    rb_status = rollback.get("status")
    if rb_status:
        lines.extend(["", "ROLLBACK", f"  Status:       {rb_status}", f"  Detail:       {rollback.get('detail') or ''}"])

    limitations = attrib.get("limitations") or []
    if limitations:
        lines.append("")
        lines.append("LIMITATIONS")
        for item in limitations:
            lines.append(f"  - {item}")

    lines.append("")
    lines.append("RECOMMENDED NEXT STEPS")
    for step in _recommended_steps(record):
        lines.append(f"  - {step}")

    lines.append("=" * 72)
    return "\n".join(lines)


def format_proxy_state_change_v1(record: dict[str, Any]) -> str:
    """Format legacy monitor_proxy.ps1 ``proxy_state_change`` rows (schema v1)."""

    record = normalize_watch_record(record)
    ts = record.get("timestamp_utc") or record.get("timestamp") or "unknown"
    old_en = record.get("old_enable") if "old_enable" in record else (record.get("before_snapshot") or {}).get("proxy_enable")
    new_en = record.get("new_enable") if "new_enable" in record else (record.get("after_snapshot") or {}).get("proxy_enable")
    old_srv = record.get("old_server_masked") or (record.get("before_snapshot") or {}).get("proxy_server") or "?"
    new_srv = record.get("new_server_masked") or (record.get("after_snapshot") or {}).get("proxy_server") or "?"
    lines = [
        "=" * 72,
        "PROXY MONITOR - REGISTRY CHANGE (schema v1, normalized on read)",
        "=" * 72,
        f"Time (UTC):     {ts}",
        f"Summary:        {_headline_for_transition({'proxy_enable': old_en, 'proxy_server': old_srv}, {'proxy_enable': new_en, 'proxy_server': new_srv})}",
        f"ProxyEnable:    {_proxy_on_label(old_en)}  ->  {_proxy_on_label(new_en)}",
        f"ProxyServer:    {old_srv}  ->  {new_srv}",
        "Note:           [IP] means localhost was masked in the log (usually 127.0.0.1:<port>).",
    ]
    try:
        if int(new_en) == 1:
            lines.append("Impact:         HIGH - system proxy ON; not an approval to keep proxy enabled.")
        elif int(old_en) == 1 and int(new_en) == 0:
            lines.append("Impact:         Proxy disabled; watch for OFF -> ON (ACTIVE_REVERTER).")
    except (TypeError, ValueError):
        pass

    procs = record.get("recent_processes")
    if procs:
        lines.append("")
        lines.extend(format_cpu_process_snapshot([str(p) for p in procs if p]))

    lines.append("")
    lines.append("UPGRADE: python -m src proxy-guard --interval 5  (schema v2 + ListenerCorrelation)")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_watch_record(record: dict[str, Any]) -> str:
    """Dispatch formatter by schema_version / event type."""

    rec = normalize_watch_record(record)
    if rec.get("event") == "proxy_state_change":
        return format_proxy_state_change_v1(rec)
    if rec.get("schema_version") == 1:
        return format_proxy_state_change_v1(rec)
    return format_proxy_guard_change(rec)


def format_watch_report(
    records: list[dict[str, Any]],
    *,
    path: Path | None = None,
    total_rows: int | None = None,
    all_records_for_flip_flop: list[dict[str, Any]] | None = None,
) -> str:
    """Format multiple watch rows for terminal output."""

    if not records:
        where = str(path) if path else "reports/proxy_guard_watch.jsonl"
        return f"No proxy watch events found in {where}."

    header = [
        "PROXY GUARD WATCH REPORT",
        "-" * 72,
        "Canonical audit: reports/proxy_guard_watch.jsonl",
        "Legacy mirrors: logs/proxy_guard_audit.jsonl, logs/proxy_hijack_audit.jsonl (scan-only)",
    ]
    if path:
        header.append(f"Source: {path}")
    if total_rows is not None:
        header.append(f"Showing last {len(records)} of {total_rows} event(s)")
    else:
        header.append(f"Showing last {len(records)} event(s)")

    analysis_source = all_records_for_flip_flop if all_records_for_flip_flop is not None else records
    incident = detect_active_reverter(analysis_source)
    if incident:
        header.append("")
        header.append(format_active_reverter_incident(incident))

    v1_count = sum(
        1
        for r in records
        if r.get("event") == "proxy_state_change" or r.get("schema_version") == 1
    )
    if v1_count == len(records) and len(records) > 0:
        header.append(
            "Format: schema v1 rows normalized on read. Prefer python -m src proxy-guard for v2."
        )
    header.append("")

    blocks = ["\n".join(header)]
    for idx, rec in enumerate(records, start=1):
        blocks.append(f"[{idx}/{len(records)}]")
        blocks.append(format_watch_record(rec))
        blocks.append("")
    return "\n".join(blocks).rstrip() + "\n"

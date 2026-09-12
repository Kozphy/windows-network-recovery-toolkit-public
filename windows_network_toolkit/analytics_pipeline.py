"""Endpoint evidence analytics pipeline orchestration.

Module responsibility:
    Normalize audit JSONL or fixtures into ``EvidenceEvent`` records, classify incidents,
    run control tests, compute risk scores, and build dashboard aggregates for export/API.

System placement:
    Central orchestrator for ``analytics-summary``, ``analytics-export``, ``evidence-report
    --analytics``, and ``backend/technology_risk_routes``. Sits above ``evidence_schema``,
    ``incident_classifier``, ``control_tests``, ``analytics``, and ``risk_scoring_engine``.

Pipeline stages:
    1. Load audit rows or fixture dict
    2. ``normalize_events_*`` → ``EvidenceEvent[]``
    3. ``classify_incidents_from_events`` → ``IncidentRecord[]``
    4. ``map_control_tests_from_incident`` per incident
    5. ``build_dashboard_dataset`` + ``score_risk_from_incident`` per incident

Key invariants:
    * Read-only — no host mutation.
    * Output ``schema_version``: ``endpoint_evidence_analytics.v1``.
    * Timestamps in evidence are UTC ISO-8601 strings (``Z`` suffix where generated).
    * Duplicate ``event_id`` values deduplicated in audit normalization.

Side effects:
    ``export_endpoint_analytics`` writes JSON/CSV files under ``out_dir``.

Idempotency:
    Pipeline functions are deterministic for identical inputs.
    File export overwrites target paths.

Failure modes:
    Empty audit dir yields zero events and INSUFFICIENT_DATA-style incidents.
    Malformed JSONL lines skipped only where ``load_audit_rows`` cannot parse (raises on bad JSON).

Audit Notes:
    * Risk scores are ordinal — verify ``limitations[]`` before committee use.
    * Do not treat listener process names as registry writer proof without T4 tier.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from windows_network_toolkit.analytics import build_dashboard_dataset
from windows_network_toolkit.audit_store import audit_dir, read_audit_logs
from windows_network_toolkit.control_tests import (
    EndpointControlTestResult,
    map_control_tests_from_incident,
    run_endpoint_control_tests,
)
from windows_network_toolkit.evidence_schema import (
    EvidenceEvent,
    events_to_json,
    normalize_listener_state,
    normalize_probe_result,
    normalize_proxy_change_event,
    normalize_proxy_state,
)
from windows_network_toolkit.incident_classifier import classify_incidents_from_events
from windows_network_toolkit.risk_scoring_engine import score_risk_from_incident


def load_audit_rows(*, input_path: Path | None = None) -> list[dict[str, Any]]:
    """Load raw audit rows from JSONL file, JSON file, or directory of JSONL files.

    Args:
        input_path: File or directory path. When None, reads from default audit dir via
            ``read_audit_logs``.

    Returns:
        List of parsed JSON objects (one per JSONL line or array element).

    Raises:
        json.JSONDecodeError: On invalid JSON in a file.

    Data handling:
        Directory paths merge all ``*.jsonl`` files in sorted order.
        Dict wrappers with ``audit_rows`` key unwrap to that list.
    """
    if input_path is None:
        return read_audit_logs(pattern="*.jsonl")
    if input_path.is_file():
        text = input_path.read_text(encoding="utf-8")
        if input_path.suffix == ".jsonl":
            rows: list[dict[str, Any]] = []
            for line in text.splitlines():
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
            return rows
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "audit_rows" in data:
            return list(data["audit_rows"])
        return [data]
    if input_path.is_dir():
        rows: list[dict[str, Any]] = []
        for path in sorted(input_path.glob("*.jsonl")):
            rows.extend(load_audit_rows(input_path=path))
        return rows
    return []


def normalize_events_from_fixture(fixture: dict[str, Any]) -> list[EvidenceEvent]:
    """Normalize an in-memory fixture dict into a list of typed evidence events.

    Args:
        fixture: Dict with optional keys: ``proxy_state``, ``proxy_owner``,
            ``health_audit``, ``health_inject``, ``timeline``, and ``evidence_events``.
            Matches the shape emitted by ``collect-evidence-bundle`` JSON output.

    Returns:
        List of ``EvidenceEvent`` objects for each recognized sub-section of the fixture.
        Unrecognized keys are silently skipped.

    Side effects:
        None.
    """
    events: list[EvidenceEvent] = []
    if fixture.get("proxy_state"):
        events.append(normalize_proxy_state(fixture["proxy_state"], source_command="fixture"))
    if fixture.get("proxy_owner"):
        events.append(normalize_listener_state(fixture["proxy_owner"], source_command="fixture"))
    health_row = fixture.get("health_audit") or {}
    if fixture.get("health_inject"):
        health_row = {
            "timestamp_utc": fixture["health_inject"].get("timestamp_utc"),
            "health": fixture["health_inject"],
        }
    if health_row:
        events.append(normalize_probe_result(health_row, source_command="proxy-health"))
    for item in fixture.get("timeline") or []:
        if item.get("new_state") or item.get("old_state"):
            events.append(normalize_proxy_change_event(item, source_command="proxy-watch"))
    for row in fixture.get("evidence_events") or []:
        events.append(
            EvidenceEvent(
                **{k: v for k, v in row.items() if k in EvidenceEvent.__dataclass_fields__}
            )
        )
    return events


def normalize_events_from_audit_rows(rows: list[dict[str, Any]]) -> list[EvidenceEvent]:
    """Normalize raw JSONL audit rows into typed evidence events, deduplicating by event_id.

    Args:
        rows: Raw JSON objects from ``load_audit_rows``; may contain ``proxy_change``,
            ``poll``, ``initial_poll``, ``proxy_health_check``, proxy-state dicts,
            listener dicts, and legacy attribution rows.

    Returns:
        Deduplicated list of ``EvidenceEvent`` objects in input order; rows that cannot
        be classified as a known event type are silently skipped.

    Side effects:
        None.

    Audit Notes:
        Deduplication is by ``event_id`` only — rows with distinct ids but identical
        content are treated as separate evidence observations.
    """
    events: list[EvidenceEvent] = []
    for row in rows:
        event_type = row.get("event")
        if event_type == "proxy_change":
            events.append(normalize_proxy_change_event(row, source_command="proxy-watch"))
            if row.get("health_audit"):
                events.append(
                    normalize_probe_result(row["health_audit"], source_command="proxy-health")
                )
            if row.get("owner"):
                events.append(normalize_listener_state(row["owner"], source_command="proxy-owner"))
            state = row.get("new_state")
            if state:
                events.append(normalize_proxy_state(state, source_command="proxy-watch"))
        elif event_type in ("poll", "initial_poll") and row.get("state"):
            events.append(normalize_proxy_state(row["state"], source_command="proxy-watch"))
        elif event_type == "proxy_health_check" or row.get("health"):
            events.append(normalize_probe_result(row, source_command="proxy-health"))
        elif (
            row.get("wininet_proxy_server") is not None
            or row.get("wininet_proxy_enabled") is not None
        ):
            events.append(normalize_proxy_state(row, source_command="audit"))
        elif row.get("listener_found") is not None:
            events.append(normalize_listener_state(row, source_command="proxy-owner"))
        elif row.get("diff") and row.get("attribution"):
            diff = row.get("diff") or {}
            events.append(
                normalize_proxy_change_event(
                    {
                        "timestamp_utc": row.get("timestamp") or row.get("timestamp_utc"),
                        "old_state": {
                            "wininet_proxy_server": (diff.get("before") or {}).get("proxy_server"),
                            "wininet_proxy_enabled": (diff.get("before") or {}).get("proxy_enable"),
                        },
                        "new_state": {
                            "wininet_proxy_server": (diff.get("after") or {}).get("proxy_server"),
                            "wininet_proxy_enabled": (diff.get("after") or {}).get("proxy_enable"),
                        },
                        "reverter_diagnosis": row.get("reverter_diagnosis"),
                    },
                    source_command="proxy-watch",
                )
            )
            health_audit = (row.get("attribution") or {}).get("health_audit")
            if health_audit:
                events.append(normalize_probe_result(health_audit, source_command="proxy-health"))
    return _dedupe_events(events)


def _dedupe_events(events: list[EvidenceEvent]) -> list[EvidenceEvent]:
    seen: set[str] = set()
    out: list[EvidenceEvent] = []
    for ev in events:
        if ev.event_id in seen:
            continue
        seen.add(ev.event_id)
        out.append(ev)
    return out


def run_endpoint_analytics_pipeline(
    *,
    input_path: Path | None = None,
    fixture: dict[str, Any] | None = None,
    bucket: str = "day",
    limit_processes: int = 10,
) -> dict[str, Any]:
    """Run evidence → classification → control tests → risk scores → dashboard dataset.

    Args:
        input_path: Audit JSONL path or directory when ``fixture`` is None.
        fixture: In-memory fixture dict for tests and portfolio demos.
        bucket: Timeline bucket granularity: ``day`` or ``hour``.
        limit_processes: Cap for top_listener_processes chart rows.

    Returns:
        Dict with schema_version, evidence_events, incidents, control_tests,
        risk_scores, dashboard_dataset, and limitations.

    Side effects:
        None (read-only). May read audit files from disk.

    Idempotency:
        Deterministic for identical inputs.
    """
    if fixture:
        events = normalize_events_from_fixture(fixture)
    else:
        path = input_path or audit_dir()
        rows = load_audit_rows(input_path=path if path != audit_dir() or path.exists() else None)
        events = normalize_events_from_audit_rows(rows)

    incidents = classify_incidents_from_events(events)
    control_results: list[EndpointControlTestResult] = []
    for incident in incidents:
        control_results.extend(map_control_tests_from_incident(incident, events))
    if not control_results and incidents:
        control_results = run_endpoint_control_tests(
            proxy_state=(events[0].raw_snapshot if events else {}),
            health_audit=None,
        )

    dashboard = build_dashboard_dataset(
        events,
        incidents,
        control_results,
        bucket=bucket,
    )
    dashboard["charts"]["top_listener_processes"] = dashboard["charts"]["top_listener_processes"][
        :limit_processes
    ]

    payload = {
        "schema_version": "endpoint_evidence_analytics.v1",
        "evidence_events": events_to_json(events),
        "incidents": [i.to_dict() for i in incidents],
        "control_tests": [c.to_dict() for c in control_results],
        "dashboard_dataset": dashboard,
        "limitations": list({lim for ev in events for lim in ev.limitations}),
    }
    control_dicts = payload["control_tests"]
    payload["risk_scores"] = [
        {
            **score_risk_from_incident(inc, control_tests=control_dicts).to_dict(),
            "incident_id": inc.get("incident_id"),
        }
        for inc in payload["incidents"]
    ]
    return payload


def format_endpoint_analytics_summary_human(payload: dict[str, Any]) -> str:
    """Format an analytics pipeline payload as a human-readable terminal summary.

    Args:
        payload: Output of ``run_endpoint_analytics_pipeline``.

    Returns:
        Multi-line string with headline counts, incident class distribution, control
        result distribution, and limitations. Suitable for CLI operator output.

    Side effects:
        None.
    """
    dash = payload.get("dashboard_dataset") or {}
    summary = dash.get("summary") or {}
    lines = [
        "=== Endpoint Evidence Analytics Summary ===",
        "",
        f"Evidence events: {summary.get('total_evidence_events', 0)}",
        f"Incidents: {summary.get('total_incidents', 0)}",
        f"High risk incidents: {summary.get('high_risk_incidents', 0)}",
        f"Control failures: {summary.get('control_failures', 0)}",
        f"Reverter suspected: {summary.get('reverter_suspected_count', 0)}",
        "",
        "Incident classes:",
    ]
    for row in (dash.get("charts") or {}).get("incident_classes") or []:
        lines.append(f"  - {row.get('incident_class')}: {row.get('count')}")
    lines.append("")
    lines.append("Control results:")
    for row in (dash.get("charts") or {}).get("control_results") or []:
        lines.append(f"  - {row.get('test_result')}: {row.get('count')}")
    lines.append("")
    lines.append("Limitations:")
    for lim in payload.get("limitations") or []:
        lines.append(f"  - {lim}")
    return "\n".join(lines)


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = sorted({k for row in rows for k in row})
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def render_analytics_evidence_report(payload: dict[str, Any]) -> str:
    """Render a Markdown report from an analytics pipeline payload.

    Args:
        payload: Output of ``run_endpoint_analytics_pipeline``.

    Returns:
        Markdown string with executive summary, incident class distribution, risk level
        distribution, top listener processes (correlation-only), direct-vs-proxy outcomes,
        control test summary, evidence tier summary, key limitations, and recommended
        next proof steps.

    Side effects:
        None.

    Audit Notes:
        Listener process names in the report are correlation-only — label them accordingly
        when presenting to governance committees.
    """
    dash = payload.get("dashboard_dataset") or {}
    summary = dash.get("summary") or {}
    charts = dash.get("charts") or {}
    lines = [
        "# Endpoint evidence analytics report",
        "",
        "## Executive summary",
        "",
        f"- Total evidence events: **{summary.get('total_evidence_events', 0)}**",
        f"- Total incidents: **{summary.get('total_incidents', 0)}**",
        f"- High-risk incidents: **{summary.get('high_risk_incidents', 0)}**",
        f"- Control failures: **{summary.get('control_failures', 0)}**",
        f"- Reverter suspected count: **{summary.get('reverter_suspected_count', 0)}**",
        "",
        "> This is not malware detection, EDR/XDR, or autonomous remediation. "
        "It is an evidence-based endpoint reliability and technology risk analytics toolkit.",
        "",
        "## Incident class distribution",
        "",
    ]
    for row in charts.get("incident_classes") or []:
        lines.append(f"- `{row.get('incident_class')}`: {row.get('count')}")
    lines.extend(["", "## Risk level distribution", ""])
    for row in charts.get("risk_levels") or []:
        lines.append(f"- `{row.get('risk_level')}`: {row.get('count')}")
    lines.extend(["", "## Top listener processes (correlation only)", ""])
    for row in charts.get("top_listener_processes") or []:
        lines.append(f"- `{row.get('process_name')}`: {row.get('count')}")
    lines.extend(["", "## Direct vs proxy outcomes", ""])
    for row in charts.get("direct_vs_proxy_outcomes") or []:
        lines.append(f"- `{row.get('outcome')}`: {row.get('count')}")
    lines.extend(["", "## Control test summary", ""])
    for ctrl in payload.get("control_tests") or []:
        lines.append(
            f"- **{ctrl.get('control_id')}**: {ctrl.get('test_result')} (risk {ctrl.get('risk')})"
        )
    lines.extend(["", "## Evidence tier summary", ""])
    for row in charts.get("evidence_tiers") or []:
        lines.append(f"- `{row.get('evidence_tier')}`: {row.get('count')}")
    lines.extend(["", "## Key limitations", ""])
    for lim in payload.get("limitations") or []:
        lines.append(f"- {lim}")
    lines.extend(
        [
            "",
            "## Recommended next proof steps",
            "",
            "- Enable Sysmon Event ID 13 or Procmon registry trace for writer proof (T4).",
            "- Run `proxy-watch --format human` during reproduction windows.",
            "- Run `proxy-health --json` before any preview remediation.",
            "- Export analytics CSV for Power BI governance dashboards.",
        ]
    )
    return "\n".join(lines)


def export_endpoint_analytics(
    payload: dict[str, Any],
    out_dir: Path,
    *,
    export_csv: bool = True,
) -> dict[str, str]:
    """Write JSON and optional CSV analytics artefacts to ``out_dir``.

    Args:
        payload: Output of ``run_endpoint_analytics_pipeline``.
        out_dir: Destination directory (created if missing).
        export_csv: When True, write chart CSV files for Power BI import.

    Returns:
        Map of filename → absolute path.

    Side effects:
        Creates ``out_dir`` and overwrites existing files with the same names.

    Audit Notes:
        Exported data may contain endpoint hostnames from evidence — review before sharing.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, str] = {}
    json_files = {
        "evidence_events.json": payload.get("evidence_events") or [],
        "incidents.json": payload.get("incidents") or [],
        "control_tests.json": payload.get("control_tests") or [],
        "dashboard_dataset.json": payload.get("dashboard_dataset") or {},
    }
    for name, data in json_files.items():
        path = out_dir / name
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        paths[name] = str(path.resolve())

    if export_csv:
        charts = (payload.get("dashboard_dataset") or {}).get("charts") or {}
        csv_map = {
            "incident_classes.csv": charts.get("incident_classes") or [],
            "risk_levels.csv": charts.get("risk_levels") or [],
            "control_results.csv": charts.get("control_results") or [],
            "top_listener_processes.csv": charts.get("top_listener_processes") or [],
            "direct_vs_proxy_outcomes.csv": charts.get("direct_vs_proxy_outcomes") or [],
            "evidence_tiers.csv": charts.get("evidence_tiers") or [],
            "timeline.csv": charts.get("timeline") or [],
        }
        for name, rows in csv_map.items():
            path = out_dir / name
            _write_csv(path, rows)
            paths[name] = str(path.resolve())
    return paths

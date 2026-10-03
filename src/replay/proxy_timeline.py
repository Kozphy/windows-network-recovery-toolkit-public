"""Proxy incident timeline builder — Step 4."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import ProxyTimelineEvent, ProxyTimelineEventType


def _parse_ts(value: str | None) -> str:
    if not value:
        return ""
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return value or ""


def _load_repair_audit(repo_root: Path, since_seconds: int) -> list[dict[str, Any]]:
    path = repo_root / "logs" / "repair_audit.jsonl"
    if not path.is_file():
        return []
    datetime.now(UTC).timestamp() - since_seconds
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                blob = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(blob, dict):
                rows.append(blob)
    except OSError:
        return []
    return rows


def build_proxy_timeline(
    *,
    transition_rows: list[dict[str, Any]],
    causation_results: list[dict[str, Any]] | None = None,
    policy_decisions: list[dict[str, Any]] | None = None,
    classifications: list[dict[str, Any]] | None = None,
    sysmon_events: list[dict[str, Any]] | None = None,
    repo_root: Path | None = None,
    since_seconds: int = 3600,
    incident_ids: list[str] | None = None,
) -> list[ProxyTimelineEvent]:
    """Merge artefacts into chronologically sorted timeline events."""
    events: list[ProxyTimelineEvent] = []
    causation_results = causation_results or []
    policy_decisions = policy_decisions or []
    classifications = classifications or []
    sysmon_events = sysmon_events or []
    incident_ids = incident_ids or []

    for idx, row in enumerate(transition_rows):
        iid = (
            incident_ids[idx]
            if idx < len(incident_ids)
            else str(row.get("incident_id") or f"incident-{idx}")
        )
        ts = _parse_ts(str(row.get("timestamp") or ""))
        diff = row.get("diff") or {}
        before = diff.get("before") or {}
        after = diff.get("after") or {}
        caus = row.get("causation") or (
            causation_results[idx] if idx < len(causation_results) else {}
        )

        if isinstance(caus, dict) and caus.get("writer_process"):
            events.append(
                ProxyTimelineEvent(
                    timestamp_utc=ts,
                    event_type=ProxyTimelineEventType.PROCESS_CREATED,
                    source="sysmon/eid1",
                    title=f"{caus.get('parent_process') or 'parent'} launched {caus.get('writer_process')}",
                    details=caus.get("writer_command_line") or "",
                    process_guid=caus.get("writer_process_guid"),
                    process_id=caus.get("writer_pid"),
                    confidence=float(caus.get("confidence") or 0.85),
                    raw_reference=caus,
                    incident_id=iid,
                )
            )

        if isinstance(caus, dict) and caus.get("matched_registry_target"):
            events.append(
                ProxyTimelineEvent(
                    timestamp_utc=ts,
                    event_type=ProxyTimelineEventType.REGISTRY_VALUE_SET,
                    source="sysmon/eid13",
                    title=f"{caus.get('writer_process')} wrote {caus.get('matched_registry_target')}",
                    details=str(caus.get("matched_registry_details") or ""),
                    confidence=float(caus.get("confidence") or 0.9),
                    raw_reference=caus,
                    incident_id=iid,
                )
            )

        suspect = (row.get("attribution") or {}).get("primary_suspect")
        if isinstance(suspect, dict) and suspect.get("name"):
            port = (
                after.get("proxy_server") or caus.get("observed_localhost_port")
                if isinstance(caus, dict)
                else None
            )
            events.append(
                ProxyTimelineEvent(
                    timestamp_utc=ts,
                    event_type=ProxyTimelineEventType.LOCALHOST_LISTENER_OBSERVED,
                    source="proxy-watch",
                    title=f"{suspect.get('name')} listening on {port or 'localhost'}",
                    details=f"pid={suspect.get('pid')} parent={suspect.get('parent_name')}",
                    confidence=float((row.get("attribution") or {}).get("confidence") or 0.45),
                    raw_reference=suspect,
                    incident_id=iid,
                )
            )

        events.append(
            ProxyTimelineEvent(
                timestamp_utc=ts,
                event_type=ProxyTimelineEventType.PROXY_STATE_CHANGED,
                source="proxy-watch",
                title="WinINET proxy state changed",
                details=f"ProxyEnable {before.get('proxy_enable')} -> {after.get('proxy_enable')}; "
                f"ProxyServer {before.get('proxy_server')} -> {after.get('proxy_server')}",
                confidence=0.95,
                raw_reference=diff,
                incident_id=iid,
            )
        )

        cls = classifications[idx] if idx < len(classifications) else {}
        if cls:
            events.append(
                ProxyTimelineEvent(
                    timestamp_utc=ts,
                    event_type=ProxyTimelineEventType.CLASSIFICATION_ASSIGNED,
                    source="process_classifier",
                    title=str(cls.get("classification") or cls.get("label") or "UNKNOWN"),
                    details=str(cls.get("summary") or cls.get("explanation") or ""),
                    confidence=float(cls.get("confidence") or 0.5),
                    raw_reference=cls,
                    incident_id=iid,
                )
            )

        pol = policy_decisions[idx] if idx < len(policy_decisions) else {}
        if pol:
            events.append(
                ProxyTimelineEvent(
                    timestamp_utc=ts,
                    event_type=ProxyTimelineEventType.POLICY_DECISION_CREATED,
                    source="proxy_policy_engine",
                    title=f"{pol.get('decision') or pol.get('action')} / {pol.get('severity', 'MEDIUM')}",
                    details=str(pol.get("reason") or ""),
                    confidence=float(pol.get("confidence") or 0.6),
                    raw_reference=pol,
                    incident_id=iid,
                )
            )

    for ev in sysmon_events:
        eid = ev.get("EventID") or ev.get("event_id")
        ts = _parse_ts(str(ev.get("UtcTime") or ev.get("utc_time") or ""))
        if eid == 1:
            events.append(
                ProxyTimelineEvent(
                    timestamp_utc=ts,
                    event_type=ProxyTimelineEventType.PROCESS_CREATED,
                    source="sysmon",
                    title=f"Process create: {ev.get('Image')}",
                    details=ev.get("CommandLine") or "",
                    raw_reference=ev,
                )
            )

    if repo_root is not None:
        for audit in _load_repair_audit(repo_root, since_seconds):
            ts = _parse_ts(str(audit.get("timestamp") or audit.get("timestamp_utc") or ""))
            if audit.get("dry_run") is True and audit.get("subtype") == "proxy_disable":
                events.append(
                    ProxyTimelineEvent(
                        timestamp_utc=ts,
                        event_type=ProxyTimelineEventType.REMEDIATION_PREVIEWED,
                        source="repair_audit",
                        title="Remediation preview: proxy-disable",
                        details="Dry-run only — no registry mutation",
                        raw_reference=audit,
                    )
                )
            if audit.get("confirm") or audit.get("confirmation"):
                events.append(
                    ProxyTimelineEvent(
                        timestamp_utc=ts,
                        event_type=ProxyTimelineEventType.USER_CONFIRMATION_REQUIRED,
                        source="repair_audit",
                        title="User confirmation recorded",
                        details=str(audit.get("confirm") or audit.get("confirmation")),
                        raw_reference=audit,
                    )
                )
            if audit.get("dry_run") is False and audit.get("subtype") == "proxy_disable":
                events.append(
                    ProxyTimelineEvent(
                        timestamp_utc=ts,
                        event_type=ProxyTimelineEventType.PROXY_DISABLED_CONFIRMED,
                        source="repair_audit",
                        title="Proxy disabled (confirmed remediation)",
                        details="Confirmed operator remediation",
                        raw_reference=audit,
                    )
                )

    events.sort(key=lambda e: e.sort_key())
    return events


def build_timeline_from_fixture(
    fixture: dict[str, Any], *, repo_root: Path | None = None
) -> list[ProxyTimelineEvent]:
    """Build timeline from a single incident fixture blob."""
    from src.proxy_guard.incident_pipeline import analyze_fixture

    bundle = analyze_fixture(fixture, repo_root=repo_root or Path.cwd())
    row = bundle["transition"]
    return build_proxy_timeline(
        transition_rows=[row],
        causation_results=[bundle["causation"]],
        classifications=[bundle["classification"]],
        policy_decisions=[bundle["policy"]],
        incident_ids=[bundle["incident_id"]],
    )


def build_timeline_around(
    repo_root: Path,
    anchor_utc: str,
    *,
    window_seconds: int = 30,
    run: Any = None,
) -> list[ProxyTimelineEvent]:
    """Timeline for transitions within ±window of anchor timestamp."""
    from src.proxy_guard.audit import proxy_change_audit_jsonl_path
    from src.proxy_guard.incident_pipeline import analyze_incident_from_row

    anchor = datetime.fromisoformat(anchor_utc.replace("Z", "+00:00")).astimezone(UTC)
    win = timedelta(seconds=window_seconds)
    path = proxy_change_audit_jsonl_path(repo_root)
    rows: list[dict[str, Any]] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                blob = json.loads(line.strip())
            except (json.JSONDecodeError, ValueError):
                continue
            if blob.get("event") != "proxy_change_detected":
                continue
            ts = datetime.fromisoformat(str(blob.get("timestamp", "")).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            ts = ts.astimezone(UTC)
            if anchor - win <= ts <= anchor + win:
                rows.append(blob)

    bundles = [analyze_incident_from_row(r, repo_root=repo_root, run=run) for r in rows]
    return build_proxy_timeline(
        transition_rows=rows,
        causation_results=[b["causation"] for b in bundles],
        classifications=[b["classification"] for b in bundles],
        policy_decisions=[b["policy"] for b in bundles],
        repo_root=repo_root,
        since_seconds=window_seconds * 2,
    )


def render_timeline_json(events: list[ProxyTimelineEvent]) -> str:
    """Render timeline json.

    Args:
        events: The events value supplied by the caller.

    Returns:
        The str result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return json.dumps({"events": [e.to_dict() for e in events]}, indent=2)


def render_timeline_markdown(events: list[ProxyTimelineEvent]) -> str:
    """Render timeline markdown.

    Args:
        events: The events value supplied by the caller.

    Returns:
        The str result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    lines = ["# Proxy incident timeline", ""]
    for ev in events:
        t = ev.timestamp_utc.split("T")[-1].replace("Z", "") if ev.timestamp_utc else "??:??:??"
        lines.append(f"## {t} {ev.event_type.value}")
        lines.append(f"- **{ev.title}**")
        if ev.details:
            lines.append(f"- {ev.details}")
        lines.append("")
    return "\n".join(lines)


def render_timeline_text(events: list[ProxyTimelineEvent]) -> str:
    """Render timeline text.

    Args:
        events: The events value supplied by the caller.

    Returns:
        The str result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    lines = ["=== Proxy incident timeline ===", ""]
    for ev in events:
        lines.append(f"{ev.timestamp_utc} {ev.event_type.value}")
        lines.append(f"  {ev.title}")
        if ev.details:
            lines.append(f"  {ev.details}")
        lines.append("")
    return "\n".join(lines)

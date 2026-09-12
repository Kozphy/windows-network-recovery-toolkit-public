"""Fixture-based fleet simulation — no live endpoint mutation."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from platform_core.models import utc_now_iso


def _repo_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    return Path(__file__).resolve().parents[1]


def fleet_demo_dir(repo_root: Path | None = None) -> Path:
    """Provide fleet demo dir behavior for toolkit workflows.

    Args:
        repo_root: Value supplied by the caller for repo root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    root = _repo_root(repo_root)
    path = root / "platform_data_fleet_demo"
    path.mkdir(parents=True, exist_ok=True)
    return path


def load_fleet_scenario(name: str, *, repo_root: Path | None = None) -> dict[str, Any]:
    """Load fleet scenario for toolkit workflows.

    Args:
        name: Value supplied by the caller for name.
        repo_root: Value supplied by the caller for repo root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    root = _repo_root(repo_root)
    path = root / "fixtures" / "fleet" / f"{name}.json"
    if not path.is_file():
        path = root / "fixtures" / "fleet" / f"{name.replace('-', '_')}.json"
    if not path.is_file():
        raise FileNotFoundError(f"fleet scenario not found: {name}")
    blob = json.loads(path.read_text(encoding="utf-8"))
    return blob if isinstance(blob, dict) else {}


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, separators=(",", ":")) + "\n")


_INCIDENT_PROFILES: tuple[dict[str, str], ...] = (
    {
        "evidence_level": "OBSERVED_ONLY",
        "proof_status": "observation",
        "severity": "low",
        "category": "healthy",
    },
    {
        "evidence_level": "CORRELATED",
        "proof_status": "correlation",
        "severity": "medium",
        "category": "proxy_drift",
    },
    {
        "evidence_level": "PROVEN_REGISTRY_WRITER",
        "proof_status": "proven",
        "severity": "medium",
        "category": "proxy_drift",
    },
    {
        "evidence_level": "FINAL_CAUSATION",
        "proof_status": "final_causation",
        "severity": "high",
        "category": "proxy_drift",
    },
    {
        "evidence_level": "OBSERVED_ONLY",
        "proof_status": "unavailable",
        "severity": "high",
        "category": "external_proxy",
    },
)


def run_fleet_simulation(
    *,
    scenario: str,
    endpoints: int = 25,
    incidents: int | None = None,
    repo_root: Path | None = None,
    out_dir: Path | None = None,
) -> dict[str, Any]:
    """Generate synthetic endpoint snapshots and incidents under platform_data_fleet_demo/."""
    spec = load_fleet_scenario(scenario, repo_root=repo_root)
    root = _repo_root(repo_root)
    base = out_dir or fleet_demo_dir(root)
    for name in (
        "endpoints.jsonl",
        "snapshots.jsonl",
        "failure_events.jsonl",
        "platform_signals.jsonl",
        "incidents.jsonl",
        "audit.jsonl",
        "remediation_previews.jsonl",
    ):
        p = base / name
        if p.is_file():
            p.unlink()

    now = datetime.now(UTC)
    incident_count = 0
    drift_count = 0
    template = spec.get("incident_template") or {}
    categories = spec.get("categories") or ["proxy_drift"]
    max_incidents = incidents if incidents is not None else int(spec.get("incidents", 0) or 0)
    drift_every = int(spec.get("drift_every_n", 5) or 5)

    for i in range(max(1, endpoints)):
        ep_id = f"ep-fleet-{i:04d}"
        ts = (now - timedelta(minutes=i)).isoformat()
        _append_jsonl(
            base / "endpoints.jsonl",
            {
                "endpoint_id": ep_id,
                "hostname": f"ws-demo-{i:04d}",
                "os_family": "windows",
                "last_seen": ts,
            },
        )
        _append_jsonl(
            base / "snapshots.jsonl",
            {
                "endpoint_id": ep_id,
                "timestamp": ts,
                "proxy_enable": 1 if i % drift_every == 0 else 0,
                "proxy_server": template.get("proxy_server") if i % drift_every == 0 else None,
            },
        )
        is_incident = i % drift_every == 0
        if max_incidents and incident_count >= max_incidents:
            is_incident = False
        if is_incident:
            drift_count += 1
            ev_id = f"fe-{uuid.uuid4().hex[:12]}"
            profile = _INCIDENT_PROFILES[incident_count % len(_INCIDENT_PROFILES)]
            _append_jsonl(
                base / "failure_events.jsonl",
                {
                    "event_id": ev_id,
                    "endpoint_id": ep_id,
                    "category": profile.get("category", categories[0]),
                    "severity": profile.get("severity", template.get("severity", "medium")),
                    "status": "open",
                    "timestamp": ts,
                    "summary": template.get("summary", "Synthetic proxy drift"),
                    "evidence_level": profile.get("evidence_level", "observation"),
                    "proof_status": profile.get("proof_status", "observation"),
                },
            )
            _append_jsonl(
                base / "platform_signals.jsonl",
                {
                    "kind": "proxy_registry_change",
                    "endpoint_id": ep_id,
                    "occurred_at": ts,
                    "detected_at": (now - timedelta(minutes=i - 1)).isoformat(),
                },
            )
            _append_jsonl(
                base / "incidents.jsonl",
                {
                    "incident_id": f"inc-{ep_id}",
                    "endpoint_id": ep_id,
                    "scenario": scenario,
                    "status": "open",
                    "severity": template.get("severity", "medium"),
                },
            )
            _append_jsonl(
                base / "remediation_previews.jsonl",
                {
                    "preview_id": f"prev-{ev_id}",
                    "endpoint_id": ep_id,
                    "action": "reset_proxy",
                    "timestamp": ts,
                },
            )
            _append_jsonl(
                base / "audit.jsonl",
                {
                    "audit_id": str(uuid.uuid4()),
                    "action": "remediation_preview",
                    "decision": "allowed",
                    "endpoint_id": ep_id,
                    "timestamp": ts,
                },
            )
            if incident_count % 4 == 0:
                _append_jsonl(
                    base / "audit.jsonl",
                    {
                        "audit_id": str(uuid.uuid4()),
                        "action": "replay",
                        "decision": "ok",
                        "endpoint_id": ep_id,
                        "timestamp": ts,
                    },
                )
            incident_count += 1

    summary = {
        "scenario": scenario,
        "endpoints": endpoints,
        "proxy_drift_incidents": drift_count,
        "incidents_total": incident_count,
        "output_dir": str(base),
        "generated_at": utc_now_iso(),
    }
    (base / "fleet_simulation_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    return summary


def fleet_report(*, repo_root: Path | None = None, out_dir: Path | None = None) -> dict[str, Any]:
    """Summarize last fleet simulation output."""
    root = _repo_root(repo_root)
    base = out_dir or fleet_demo_dir(root)
    summary_path = base / "fleet_simulation_summary.json"
    if summary_path.is_file():
        return json.loads(summary_path.read_text(encoding="utf-8"))
    return {
        "scenario": "none",
        "endpoints": 0,
        "proxy_drift_incidents": 0,
        "incidents_total": 0,
        "output_dir": str(base),
        "generated_at": utc_now_iso(),
    }


def render_fleet_report_markdown(report: dict[str, Any]) -> str:
    """Render fleet report markdown for toolkit workflows.

    Args:
        report: Value supplied by the caller for report.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    lines = [
        "# Fleet simulation report",
        "",
        f"- **Scenario:** {report.get('scenario')}",
        f"- **Endpoints:** {report.get('endpoints')}",
        f"- **Proxy drift incidents:** {report.get('proxy_drift_incidents')}",
        f"- **Incidents total:** {report.get('incidents_total')}",
        f"- **Output:** `{report.get('output_dir')}`",
        f"- **Generated:** {report.get('generated_at')}",
        "",
        "_Fixture-based simulation — no live endpoint mutation._",
    ]
    return "\n".join(lines) + "\n"

"""Incident store — fixture replay mode or live JSONL."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from src.proxy_guard.incident_pipeline import (
    analyze_fixture,
    analyze_incident_from_row,
)
from src.proxy_guard.proxy_transitions import load_recent_proxy_transitions
from src.replay.fixture_loader import load_all_fixtures, load_fixture
from src.replay.proxy_timeline import build_proxy_timeline, build_timeline_from_fixture


def repo_root() -> Path:
    """Repo root.
    
    Args:
        None.
    
    Returns:
        The Path result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return Path(os.environ.get("PLATFORM_REPO_ROOT", Path.cwd()))


def fixture_mode() -> bool:
    """Fixture mode.
    
    Args:
        None.
    
    Returns:
        The bool result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return os.environ.get("PLATFORM_FIXTURE_MODE", "").lower() in ("1", "true", "yes")


def list_incidents(*, since_minutes: int = 1440) -> list[dict[str, Any]]:
    """List incidents.
    
    Args:
        since_minutes: The since minutes value supplied by the caller.
    
    Returns:
        The list[dict[str, Any]] result produced by the operation.
    
    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    if fixture_mode():
        incidents = []
        for fx in load_all_fixtures():
            bundle = analyze_fixture(fx, repo_root=repo_root())
            incidents.append(_incident_summary(bundle))
        return incidents

    root = repo_root()
    rows = load_recent_proxy_transitions(root, since_seconds=since_minutes * 60, limit=100)
    out: list[dict[str, Any]] = []
    for row in rows:
        bundle = analyze_incident_from_row(row, repo_root=root)
        out.append(_incident_summary(bundle))
    return out


def get_incident(incident_id: str) -> dict[str, Any] | None:
    """Get incident.
    
    Args:
        incident_id: The incident id value supplied by the caller.
    
    Returns:
        The dict[str, Any] | None result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if fixture_mode():
        for fx in load_all_fixtures():
            bundle = analyze_fixture(fx, repo_root=repo_root())
            if bundle["incident_id"] == incident_id or fx.get("incident_id") == incident_id:
                return bundle
        # match by fixture stem
        try:
            fx = load_fixture(Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "proxy_incidents" / f"{incident_id}.json")
            return analyze_fixture(fx, repo_root=repo_root())
        except (OSError, ValueError):
            return None

    root = repo_root()
    rows = load_recent_proxy_transitions(root, since_seconds=86400, limit=200)
    for row in rows:
        bundle = analyze_incident_from_row(row, repo_root=root)
        if bundle["incident_id"] == incident_id:
            return bundle
    return None


def get_timeline(incident_id: str) -> list[dict[str, Any]]:
    """Get timeline.
    
    Args:
        incident_id: The incident id value supplied by the caller.
    
    Returns:
        The list[dict[str, Any]] result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    bundle = get_incident(incident_id)
    if bundle is None:
        return []
    if fixture_mode():
        fx_path = None
        for p in (Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "proxy_incidents").glob("*.json"):
            if p.stem == incident_id:
                fx_path = p
                break
        if fx_path:
            from src.replay.fixture_loader import load_fixture

            events = build_timeline_from_fixture(load_fixture(fx_path))
            return [e.to_dict() for e in events]
    events = build_proxy_timeline(
        transition_rows=[bundle["transition"]],
        causation_results=[bundle["causation"]],
        classifications=[bundle["classification"]],
        policy_decisions=[bundle["policy"]],
        incident_ids=[incident_id],
        repo_root=repo_root(),
    )
    return [e.to_dict() for e in events]


def _incident_summary(bundle: dict[str, Any]) -> dict[str, Any]:
    diff = (bundle.get("transition") or {}).get("diff") or {}
    after = diff.get("after") or {}
    before = diff.get("before") or {}
    caus = bundle.get("causation") or {}
    cls = bundle.get("classification") or {}
    pol = bundle.get("policy") or {}
    return {
        "incident_id": bundle.get("incident_id"),
        "timestamp_utc": (bundle.get("transition") or {}).get("timestamp"),
        "risk": diff.get("risk_level"),
        "causation_level": caus.get("causation_level"),
        "registry_writer": caus.get("writer_process"),
        "classification": cls.get("classification") or cls.get("label"),
        "policy_decision": pol.get("decision") or pol.get("action"),
        "policy_severity": pol.get("severity"),
        "proxy_before": before,
        "proxy_after": after,
        "localhost_port": caus.get("observed_localhost_port"),
        "status": bundle.get("status"),
    }

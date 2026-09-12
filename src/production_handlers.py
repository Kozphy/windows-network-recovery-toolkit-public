"""CLI handlers for production-shaped platform upgrades (read-only / fixture-safe)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _repo_root(arg: str | None) -> Path:
    if arg:
        return Path(arg).resolve()
    return Path.cwd().resolve()


def cmd_incident_review(args: argparse.Namespace) -> int:
    """Run the incident review command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    from platform_core.incident_review import (
        generate_incident_review,
        render_incident_review_json,
        render_incident_review_markdown,
    )

    incident_id = str(getattr(args, "incident_id", "") or "").strip()
    if not incident_id:
        print("incident-id is required", file=sys.stderr)
        return 2
    fmt = str(getattr(args, "review_format", "markdown") or "markdown").lower()
    try:
        review = generate_incident_review(incident_id, repo_root=_repo_root(getattr(args, "repo_root", None)))
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if fmt == "json":
        print(render_incident_review_json(review), end="")
    else:
        print(render_incident_review_markdown(review), end="")
    return 0


def cmd_policy_validate(args: argparse.Namespace) -> int:
    """Run the policy validate command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    
    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    from platform_core.policy_as_code import validate_policy_document

    path = Path(str(getattr(args, "policy_path", "") or "")).resolve()
    errors = validate_policy_document(path)
    if errors:
        for err in errors:
            print(f"INVALID: {err}", file=sys.stderr)
        return 1
    print(json.dumps({"valid": True, "path": str(path)}, indent=2))
    return 0


def cmd_fleet_simulate(args: argparse.Namespace) -> int:
    """Run the fleet simulate command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    from platform_core.fleet_simulation import run_fleet_simulation

    scenario = str(getattr(args, "fleet_scenario", "proxy-drift") or "proxy-drift")
    endpoints = int(getattr(args, "fleet_endpoints", 25) or 25)
    incidents_raw = getattr(args, "fleet_incidents", None)
    incidents = int(incidents_raw) if incidents_raw is not None else None
    summary = run_fleet_simulation(
        scenario=scenario,
        endpoints=endpoints,
        incidents=incidents,
        repo_root=_repo_root(getattr(args, "repo_root", None)),
    )
    print(json.dumps(summary, indent=2))
    return 0


def cmd_fleet_report(args: argparse.Namespace) -> int:
    """Run the fleet report command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    from platform_core.fleet_simulation import fleet_report, render_fleet_report_markdown

    report = fleet_report(repo_root=_repo_root(getattr(args, "repo_root", None)))
    fmt = str(getattr(args, "fleet_report_format", "markdown") or "markdown").lower()
    if fmt == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_fleet_report_markdown(report), end="")
    return 0

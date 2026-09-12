"""Deterministic portfolio demos — no host mutation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCENARIOS: dict[str, str] = {
    "healthy": "healthy_endpoint.json",
    "proxy-drift": "proxy_drift_correlated_only.json",
    "sysmon-writer": "sysmon_registry_writer_proven.json",
    "final-causation": "final_causation_browser_path_failure.json",
    "suspicious-external": "suspicious_external_proxy.json",
    "developer-proxy": "developer_tool_proxy_allowed.json",
    "stale-listener": "stale_localhost_proxy_listener.json",
}


def _root(arg: str | None) -> Path:
    return Path(arg).resolve() if arg else Path.cwd().resolve()


def _fixture(name: str, repo: Path) -> Path:
    fname = SCENARIOS.get(name, name if name.endswith(".json") else f"{name}.json")
    return repo / "tests" / "fixtures" / "demo" / fname


def run_demo_scenario(name: str, *, repo_root: Path | None = None) -> dict[str, Any]:
    """Run demo scenario.
    
    Args:
        name: The name value supplied by the caller.
        repo_root: Repository root used to resolve fixtures, reports, or local state.
    
    Returns:
        The dict[str, Any] result produced by the operation.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    from platform_core.demo_replay import replay_fixture_blob, report_fingerprint
    from platform_core.evidence_model import evidence_limitations, resolve_evidence_level
    from platform_core.policy_model import evaluate_endpoint_policy

    repo = _root(str(repo_root) if repo_root else None)
    blob = json.loads(_fixture(name, repo).read_text(encoding="utf-8"))
    proof = blob.get("proof_inputs") or {}
    ctx = blob.get("context") or {}
    level = resolve_evidence_level(proof)
    policy = evaluate_endpoint_policy(
        evidence_level=level,
        confidence_ordinal=float(ctx.get("confidence_ordinal", 0.5)),
        external_proxy=bool(ctx.get("external_proxy")),
        known_dev_tool=bool(ctx.get("known_dev_tool")),
        healthy_baseline=bool(ctx.get("healthy_baseline")),
    )
    next_steps = blob.get("recommended_next_steps") or []
    limitations = blob.get("limitations") or evidence_limitations(level)  # type: ignore[arg-type]
    report: dict[str, Any] = {
        "scenario_id": blob.get("scenario_id"),
        "title": blob.get("title"),
        "evidence_level": level,
        "expected_evidence_level": blob.get("expected_evidence_level"),
        "policy_decision": policy.get("decision"),
        "policy": policy,
        "expected_policy": blob.get("expected_policy"),
        "limitations": limitations,
        "recommended_next_step": next_steps[0] if next_steps else "Review fixture output",
        "recommended_next_steps": next_steps,
        "replay": replay_fixture_blob(blob),
        "host_mutation": False,
        "requires_admin": False,
    }
    report["fingerprint"] = report_fingerprint(report)
    return report


def render_markdown(report: dict[str, Any]) -> str:
    """Render markdown.
    
    Args:
        report: The report value supplied by the caller.
    
    Returns:
        The str result produced by the operation.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    pol = report.get("policy") or {}
    replay = report.get("replay") or {}
    lines = [
        f"# {report.get('title')}",
        "",
        f"**Evidence level:** `{report.get('evidence_level')}` (expected `{report.get('expected_evidence_level')}`)",
        f"**Policy decision:** `{report.get('policy_decision') or pol.get('decision')}` "
        f"(expected `{report.get('expected_policy')}`)",
        f"**Recommended next step:** {report.get('recommended_next_step')}",
        "",
        "## Limitations",
    ]
    lines.extend(f"- {x}" for x in report.get("limitations") or [])
    lines.extend(
        [
            "",
            "## Replay (deterministic)",
            f"- Action: `{replay.get('remediation_action', '—')}`",
            f"- Events replayed: {replay.get('event_count', 0)}",
            f"- Changed decisions: {replay.get('changed_decisions', 0)}",
            f"- Replay stable: {replay.get('replay_stable')}",
            f"- Fingerprint: `{report.get('fingerprint', '—')}`",
            "",
            "## Next steps",
        ]
    )
    lines.extend(f"- {x}" for x in report.get("recommended_next_steps") or [])
    lines.append("\n_Observation ≠ proof · Correlation ≠ causation · PREVIEW ≠ execute approval._\n")
    return "\n".join(lines)


def cmd_demo_scenario(args: argparse.Namespace) -> int:
    """Run the demo scenario command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    name = str(getattr(args, "demo_scenario", "healthy"))
    fmt = str(getattr(args, "demo_format", "markdown")).lower()
    report = run_demo_scenario(name, repo_root=_root(getattr(args, "repo_root", None)))
    if fmt == "json":
        print(json.dumps(report, indent=2))
    elif fmt == "both":
        print(render_markdown(report), end="")
        print("\n--- JSON ---\n")
        print(json.dumps(report, indent=2))
    else:
        print(render_markdown(report), end="")
    if report.get("expected_evidence_level") and report["evidence_level"] != report["expected_evidence_level"]:
        print("evidence mismatch", file=sys.stderr)
        return 1
    if report.get("expected_policy") and (report.get("policy") or {}).get("decision") != report["expected_policy"]:
        print("policy mismatch", file=sys.stderr)
        return 1
    return 0

"""Deterministic replay pipeline for Tier-1 demo fixtures (read-only)."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from platform_core.policy.engine import OperatorContext, evaluate
from platform_core.replay.runner import ReplaySummary, summarize_inline

# Stable remediation keys per scenario — safe, registry-backed actions only.
_SCENARIO_ACTIONS: dict[str, str] = {
    "healthy_endpoint": "inspect_proxy",
    "proxy_drift_correlated_only": "inspect_proxy",
    "sysmon_registry_writer_proven": "reset_proxy",
    "final_causation_browser_path_failure": "reset_proxy",
    "suspicious_external_proxy": "inspect_proxy",
    "stale_localhost_proxy_listener": "inspect_proxy",
    "developer_tool_proxy_allowed": "inspect_proxy",
}


def remediation_action_for_scenario(blob: dict[str, Any]) -> str:
    """Provide remediation action for scenario behavior for toolkit workflows.

    Args:
        blob: Value supplied by the caller for blob.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    scenario_id = str(blob.get("scenario_id") or "")
    return _SCENARIO_ACTIONS.get(scenario_id, "inspect_proxy")


def build_replay_events(blob: dict[str, Any]) -> list[dict[str, Any]]:
    """Build normalized replay rows from a demo fixture (no host I/O)."""
    proof = blob.get("proof_inputs") or {}
    action = remediation_action_for_scenario(blob)
    ctx = OperatorContext(role="admin", surface="cli")  # type: ignore[arg-type]
    gate = evaluate(proof, action, ctx)
    policy_decision = {
        "execute_allowed": gate.execute_allowed,
        "preview_allowed": gate.preview_allowed,
        "reason_codes": sorted(gate.reason_codes),
        "required_role": gate.required_role,
        "required_confirmation": gate.required_confirmation,
        "risk_tier": gate.risk_tier,
    }
    signals: dict[str, Any] = {
        "remediation_action": action,
        "simulated_operator_role": "admin",
        "simulated_surface": "cli",
    }
    for key, val in proof.items():
        if isinstance(val, (bool, int, float, str)):
            signals[key] = val
    return [
        {
            "schema_version": "1",
            "event_id": f"demo-replay-{blob.get('scenario_id', 'unknown')}",
            "signals": signals,
            "policy_decision": policy_decision,
        }
    ]


def replay_summary_from_events(events: list[dict[str, Any]]) -> ReplaySummary:
    """Provide replay summary from events behavior for toolkit workflows.

    Args:
        events: Value supplied by the caller for events.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    return summarize_inline(events)


def replay_fixture_blob(blob: dict[str, Any]) -> dict[str, Any]:
    """Replay demo fixture through policy gates; output is deterministic."""
    events = build_replay_events(blob)
    summary = replay_summary_from_events(events)
    return {
        "remediation_action": events[0]["signals"]["remediation_action"],
        "event_count": summary.total_events,
        "parse_errors": summary.parse_errors,
        "changed_decisions": summary.changed_decisions,
        "newly_blocked_execute": summary.newly_blocked_execute,
        "newly_allowed_preview": summary.newly_allowed_preview,
        "replay_stable": summary.changed_decisions == 0 and summary.parse_errors == 0,
    }


def report_fingerprint(report: dict[str, Any]) -> str:
    """Short stable hash for regression tests (excludes fingerprint field)."""
    payload = {k: v for k, v in report.items() if k != "fingerprint"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

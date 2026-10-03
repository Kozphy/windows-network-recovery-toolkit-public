"""Build full incident analysis from proxy-watch JSONL rows (read-only)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from src.classification.process_classifier import ProcessClassificationInput, classify_process
from src.correlation.proxy_causation import analyze_from_proxy_watch_row
from src.policy.models import ProxyPolicyInput
from src.policy.proxy_policy_engine import evaluate_proxy_policy_input, load_proxy_policy_config
from src.proxy_guard.audit import proxy_change_audit_jsonl_path
from src.replay.proxy_timeline import ProxyTimelineEvent, build_proxy_timeline
from src.reports.evidence_tree import build_evidence_tree
from src.telemetry.registry_targets import proxy_registry_value_name


def incident_id_for_row(row: dict[str, Any]) -> str:
    """Incident id for row.

    Args:
        row: The row value supplied by the caller.

    Returns:
        The str result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    ts = str(row.get("timestamp") or "")
    diff = row.get("diff") or {}
    key = json.dumps({"ts": ts, "changed": diff.get("changed_fields")}, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def load_latest_proxy_transition(repo_root: Path) -> dict[str, Any] | None:
    """Load latest proxy transition.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.

    Returns:
        The dict[str, Any] | None result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    path = proxy_change_audit_jsonl_path(repo_root)
    if not path.is_file():
        return None
    latest: dict[str, Any] | None = None
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                blob = json.loads(line)
            except json.JSONDecodeError:
                continue
            if blob.get("event") == "proxy_change_detected":
                latest = blob
    except OSError:
        return None
    return latest


def analyze_incident_from_row(
    row: dict[str, Any],
    *,
    repo_root: Path,
    window_seconds: int = 10,
    run: Any = None,
    recompute_causation: bool = False,
) -> dict[str, Any]:
    """Analyze incident from row.

    Args:
        row: The row value supplied by the caller.
        repo_root: Repository root used to resolve fixtures, reports, or local state.
        window_seconds: The window seconds value supplied by the caller.
        run: Callable used to execute the external command or probe.
        recompute_causation: The recompute causation value supplied by the caller.

    Returns:
        The dict[str, Any] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    diff = row.get("diff") or {}
    before = diff.get("before") or {}
    after = diff.get("after") or {}

    if row.get("causation") and not recompute_causation:
        causation_dict = dict(row["causation"])
    else:
        causation_dict = analyze_from_proxy_watch_row(
            row,
            window_seconds=window_seconds,
            run=run,
            repo_root=repo_root,
        ).to_dict()

    target = str(causation_dict.get("matched_registry_target") or "")
    cls_inp = ProcessClassificationInput.from_causation_dict(
        causation_dict,
        proxy_server=after.get("proxy_server"),
        registry_value_name=proxy_registry_value_name(target) or "",
    )
    classification = classify_process(cls_inp, repo_root=repo_root)

    policy_cfg = load_proxy_policy_config(repo_root)
    policy = evaluate_proxy_policy_input(
        ProxyPolicyInput(
            causation_level=str(causation_dict.get("causation_level") or "UNKNOWN"),
            classification_result=classification,
            proxy_before=before,
            proxy_after=after,
            registry_writer=causation_dict.get("writer_process"),
            registry_target=target,
            registry_details=causation_dict.get("matched_registry_details"),
            localhost_port=causation_dict.get("observed_localhost_port"),
            user_config=policy_cfg,
            timestamp_utc=str(row.get("timestamp") or ""),
            changed_fields=list(diff.get("changed_fields") or []),
            risk_level=str(diff.get("risk_level") or "medium"),
        )
    )

    tree = build_evidence_tree(
        transition_row=row,
        causation=causation_dict,
        classification=classification,
        policy=policy,
    )

    iid = incident_id_for_row(row)
    return {
        "incident_id": iid,
        "transition": row,
        "causation": causation_dict,
        "classification": classification.to_dict(),
        "policy": policy.to_dict(),
        "evidence_tree": tree.to_dict(),
        "status": _incident_status(causation_dict),
    }


def _incident_status(causation: dict[str, Any]) -> str:
    level = str(causation.get("causation_level") or "UNKNOWN")
    if level == "FINAL_CAUSATION":
        return "final_causation"
    if level in ("CORRELATION_ONLY", "UNKNOWN"):
        return "correlation_only"
    return "unknown"


def analyze_fixture(fixture: dict[str, Any], *, repo_root: Path | None = None) -> dict[str, Any]:
    """Analyze a JSON fixture (for demo/CI replay)."""
    row = fixture.get("transition") or fixture
    if fixture.get("causation"):
        row = {**row, "causation": fixture["causation"]}
    root = repo_root or Path.cwd()
    bundle = analyze_incident_from_row(
        row, repo_root=root, recompute_causation=not bool(fixture.get("causation"))
    )
    bundle["incident_id"] = str(fixture.get("incident_id") or bundle["incident_id"])
    if fixture.get("classification"):
        bundle["classification"] = fixture["classification"]
    if fixture.get("policy"):
        bundle["policy"] = fixture["policy"]
    return bundle


def build_incident_timeline(
    repo_root: Path,
    *,
    since_minutes: int = 60,
    window_seconds: int = 10,
    run: Any = None,
) -> list[ProxyTimelineEvent]:
    """Build incident timeline.

    Args:
        repo_root: Repository root used to resolve fixtures, reports, or local state.
        since_minutes: The since minutes value supplied by the caller.
        window_seconds: The window seconds value supplied by the caller.
        run: Callable used to execute the external command or probe.

    Returns:
        The list[ProxyTimelineEvent] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    from src.proxy_guard.proxy_transitions import load_recent_proxy_transitions

    rows = load_recent_proxy_transitions(repo_root, since_seconds=since_minutes * 60, limit=100)
    bundles = [
        analyze_incident_from_row(row, repo_root=repo_root, window_seconds=window_seconds, run=run)
        for row in rows
    ]
    return build_proxy_timeline(
        transition_rows=rows,
        causation_results=[b["causation"] for b in bundles],
        classifications=[b["classification"] for b in bundles],
        policy_decisions=[b["policy"] for b in bundles],
        incident_ids=[b["incident_id"] for b in bundles],
        repo_root=repo_root,
        since_seconds=since_minutes * 60,
    )

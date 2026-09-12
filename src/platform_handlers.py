"""CLI handlers for ``python -m src platform`` — uses canonical ``src.platform``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from src.platform.audit import DEFAULT_AUDIT_PATH, read_audit_tail
from src.platform.models import DecisionOutcome
from src.platform.outcome_engine import compute_metrics, metrics_to_dict
from src.platform.registry import all_adapters, get_adapter
from src.platform.replay import find_event, replay_all, run_pipeline
from src.platform.serialization import canonical_json

OUTCOMES_PATH = Path("logs/platform_decision_outcomes.jsonl")
_PIPELINE_CACHE: dict[str, Any] = {}


def _audit_path(args: argparse.Namespace) -> Path:
    custom = getattr(args, "audit_path", None)
    return Path(custom) if custom else DEFAULT_AUDIT_PATH


def _emit(payload: Any, *, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(canonical_json(payload))


def clear_platform_cache() -> None:
    """Clear platform cache.
    
    Args:
        None.
    
    Returns:
        None.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    _PIPELINE_CACHE.clear()


def _get_or_run_pipeline(event_id: str, *, audit_path: Path | None) -> Any:
    if event_id in _PIPELINE_CACHE:
        return _PIPELINE_CACHE[event_id]
    adapter, fname = find_event(event_id)
    result = run_pipeline(adapter, fixture_name=fname, audit_path=audit_path, command="decide")
    _PIPELINE_CACHE[event_id] = result
    return result


def cmd_platform_events(args: argparse.Namespace) -> int:
    """Run the platform events command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    domain = getattr(args, "platform_domain", None)
    fixture = getattr(args, "platform_fixture", None)
    adapters = [get_adapter(domain)] if domain else all_adapters()
    events: list[dict[str, Any]] = []
    for adapter in adapters:
        names = [fixture] if fixture else adapter.list_fixtures()
        for fname in names:
            if fname and fname not in adapter.list_fixtures():
                print(f"Unknown fixture: {fname}", file=sys.stderr)
                return 1
            for ev in adapter.collect_events(fname):
                events.append(ev.model_dump(mode="json"))
    _emit({"events": events, "count": len(events)}, fmt=getattr(args, "platform_format", "json"))
    return 0


def cmd_platform_evidence(args: argparse.Namespace) -> int:
    """Run the platform evidence command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    try:
        result = _get_or_run_pipeline(args.event_id, audit_path=_audit_path(args))
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    tree = [
        {
            "evidence_id": n.evidence_id,
            "description": n.description,
            "type": n.type,
            "confidence_delta": n.confidence_delta,
        }
        for n in result.evidence_result.evidence_tree
    ]
    _emit(
        {
            "event_id": args.event_id,
            "confidence_score": result.evidence_result.confidence_score,
            "ranked_hypotheses": [h.model_dump(mode="json") for h in result.evidence_result.ranked_hypotheses],
            "evidence_tree": tree,
            "explanation": result.evidence_result.explanation,
        },
        fmt=getattr(args, "platform_format", "json"),
    )
    return 0


def cmd_platform_decide(args: argparse.Namespace) -> int:
    """Run the platform decide command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    try:
        result = _get_or_run_pipeline(args.event_id, audit_path=_audit_path(args))
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    ranked = [
        {"decision": r.decision.model_dump(mode="json"), "final_score": r.final_score, "explanation": r.explanation}
        for r in result.ranked_decisions
    ]
    top = result.top_decision
    _emit(
        {
            "event_id": args.event_id,
            "fingerprint": result.fingerprint,
            "top_decision": top.model_dump(mode="json") if top else None,
            "ranked_decisions": ranked,
            "policy_note": "Recommendation is not execution permission.",
        },
        fmt=getattr(args, "platform_format", "json"),
    )
    return 0


def _append_outcome(outcome: DecisionOutcome) -> None:
    OUTCOMES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTCOMES_PATH.open("a", encoding="utf-8") as fh:
        fh.write(canonical_json(outcome.model_dump(mode="json")))
        fh.write("\n")


def _load_outcomes() -> list[DecisionOutcome]:
    if not OUTCOMES_PATH.is_file():
        return []
    return [
        DecisionOutcome.model_validate(json.loads(line))
        for line in OUTCOMES_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def cmd_platform_outcome(args: argparse.Namespace) -> int:
    """Run the platform outcome command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    decision_id = args.decision_id
    success = not bool(getattr(args, "failure", False))
    outcome = DecisionOutcome(
        outcome_id=f"out-{decision_id}",
        decision_id=decision_id,
        success=success,
        observed_result=getattr(args, "observed_result", "fixture_simulated"),
        cost_score=float(getattr(args, "cost_score", 0.1)),
        time_to_resolution_seconds=float(getattr(args, "time_to_resolution", 120.0)),
        lessons_learned=getattr(args, "lessons", "Fixture outcome recorded."),
    )
    _append_outcome(outcome)
    _emit(outcome.model_dump(mode="json"), fmt=getattr(args, "platform_format", "json"))
    return 0


def cmd_platform_replay(args: argparse.Namespace) -> int:
    """Run the platform replay command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    domain = getattr(args, "platform_domain", None)
    audit_path = _audit_path(args)
    if domain:
        adapter = get_adapter(domain)
        fixture = getattr(args, "platform_fixture", None)
        names = [fixture] if fixture else adapter.list_fixtures()
        results = [run_pipeline(adapter, fixture_name=n, audit_path=audit_path, command="replay") for n in names]
    else:
        results = replay_all(audit_path=audit_path)
    _emit(
        {
            "replayed": len(results),
            "fingerprints": [r.fingerprint for r in results],
            "events": [r.event.event_id for r in results],
        },
        fmt=getattr(args, "platform_format", "json"),
    )
    return 0


def cmd_platform_metrics(args: argparse.Namespace) -> int:
    """Run the platform metrics command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    outcomes = _load_outcomes()
    decisions_by_id: dict[str, Any] = {}
    domain_by_decision: dict[str, str] = {}
    for adapter in all_adapters():
        for fname in adapter.list_fixtures():
            try:
                result = run_pipeline(adapter, fixture_name=fname, record_audit=False)
            except Exception:
                continue
            for r in result.ranked_decisions:
                decisions_by_id[r.decision.decision_id] = r.decision
                domain_by_decision[r.decision.decision_id] = result.event.domain
    metrics = compute_metrics(outcomes, decisions_by_id, domain_by_decision=domain_by_decision)
    _emit(
        {
            "outcome_metrics": metrics_to_dict(metrics),
            "audit_rows": len(read_audit_tail(limit=100, path=_audit_path(args))),
            "fixtures_replayed": sum(len(a.list_fixtures()) for a in all_adapters()),
            "domains": [a.domain_name for a in all_adapters()],
        },
        fmt=getattr(args, "platform_format", "json"),
    )
    return 0

"""CLI for Market Event Intelligence Engine (research-only)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .audit import append_market_audit
from .calendar import default_calendar_path, get_event, load_calendar
from .evidence import build_evidence_tree
from .models import ResearchPolicyStatus
from .replay import replay_all
from .review import default_reviews_path, get_review
from .scoring import score_event
from .thesis import build_trade_thesis


def _repo_root(arg: str | None) -> Path:
    return Path(arg).resolve() if arg else Path.cwd()


def _emit(payload: object, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(payload)


def cmd_calendar(args: argparse.Namespace) -> int:
    """Run the calendar command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    root = _repo_root(args.repo_root)
    cal = Path(args.fixture) if args.fixture else default_calendar_path(root)
    events = load_calendar(cal)
    payload = [e.model_dump(mode="json") for e in events]
    _emit(payload, as_json=args.json)
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    """Run the score command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    root = _repo_root(args.repo_root)
    cal = Path(args.fixture) if args.fixture else default_calendar_path(root)
    event = get_event(args.event_id, cal)
    score = score_event(event, request_execution=bool(args.execute))
    out = score.model_dump(mode="json")
    _emit(out, as_json=args.json)
    append_market_audit(
        command="score",
        event_id=event.event_id,
        input_payload=event.model_dump(mode="json"),
        output_payload=out,
        policy_status=score.policy_status,
        explanation="Deterministic volatility/direction scoring",
        repo_root=root,
        audit_path=Path(args.audit_log) if args.audit_log else None,
    )
    return 0


def cmd_thesis(args: argparse.Namespace) -> int:
    """Run the thesis command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    root = _repo_root(args.repo_root)
    cal = Path(args.fixture) if args.fixture else default_calendar_path(root)
    event = get_event(args.event_id, cal)
    score = score_event(event, request_execution=bool(args.execute))
    thesis = build_trade_thesis(event, score)
    tree = build_evidence_tree(event, score)
    out = {
        "thesis": thesis.model_dump(mode="json"),
        "evidence_tree": tree.model_dump(mode="json"),
    }
    _emit(out, as_json=args.json)
    append_market_audit(
        command="thesis",
        event_id=event.event_id,
        input_payload=event.model_dump(mode="json"),
        output_payload=out,
        policy_status=thesis.policy_status,
        explanation="Trade thesis draft with evidence tree",
        repo_root=root,
        audit_path=Path(args.audit_log) if args.audit_log else None,
    )
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    """Run the review command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    root = _repo_root(args.repo_root)
    rev_path = Path(args.fixture) if args.fixture else default_reviews_path(root)
    review = get_review(args.event_id, rev_path)
    out = review.model_dump(mode="json")
    _emit(out, as_json=args.json)
    append_market_audit(
        command="review",
        event_id=review.event_id,
        input_payload={"event_id": review.event_id},
        output_payload=out,
        policy_status=ResearchPolicyStatus.ALLOW_RESEARCH,
        explanation="Post-event review record loaded from fixture",
        repo_root=root,
        audit_path=Path(args.audit_log) if args.audit_log else None,
    )
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Run the replay command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    root = _repo_root(args.repo_root)
    cal = Path(args.fixture) if args.fixture else default_calendar_path(root)
    rev = Path(args.reviews_fixture) if args.reviews_fixture else default_reviews_path(root)
    payload = replay_all(cal, rev if rev.is_file() else None)
    _emit(payload, as_json=args.json)
    append_market_audit(
        command="replay",
        event_id="*",
        input_payload={"calendar": str(cal), "reviews": str(rev)},
        output_payload={"scores_digest": payload["scores_digest"], "event_count": payload["event_count"]},
        policy_status=ResearchPolicyStatus.ALLOW_RESEARCH,
        explanation="Deterministic replay digest over calendar fixtures",
        repo_root=root,
        audit_path=Path(args.audit_log) if args.audit_log else None,
    )
    return 0


def _add_shared_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo-root", default=None, help="Repository root for fixtures/logs")
    parser.add_argument("--json", action="store_true", help="Emit JSON")
    parser.add_argument("--fixture", default=None, help="Override calendar or review fixture path")
    parser.add_argument("--audit-log", default=None, help="Override audit JSONL path")


def build_parser() -> argparse.ArgumentParser:
    """Build parser.
    
    Args:
        None.
    
    Returns:
        The argparse.ArgumentParser result produced by the operation.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    parser = argparse.ArgumentParser(
        prog="python -m src.market_events",
        description="Market Event Intelligence Engine — research, monitoring, replay (no trading).",
    )
    _add_shared_flags(parser)
    sub = parser.add_subparsers(dest="command", required=True)

    p_cal = sub.add_parser("calendar", help="List forward-looking events from fixtures")
    _add_shared_flags(p_cal)
    p_score = sub.add_parser("score", help="Score volatility/direction for an event")
    _add_shared_flags(p_score)
    p_score.add_argument("--event-id", required=True)
    p_score.add_argument("--execute", action="store_true", help="Simulate execution request (always blocked)")
    p_thesis = sub.add_parser("thesis", help="Generate research thesis + evidence tree")
    _add_shared_flags(p_thesis)
    p_thesis.add_argument("--event-id", required=True)
    p_thesis.add_argument("--execute", action="store_true")
    p_review = sub.add_parser("review", help="Load post-event review record")
    _add_shared_flags(p_review)
    p_review.add_argument("--event-id", required=True)
    p_replay = sub.add_parser("replay", help="Replay all events and emit deterministic digest")
    _add_shared_flags(p_replay)
    p_replay.add_argument("--reviews-fixture", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the module command-line entry point.
    
    Args:
        argv: Optional command-line argument vector supplied by the caller.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    args = build_parser().parse_args(argv)
    handlers = {
        "calendar": cmd_calendar,
        "score": cmd_score,
        "thesis": cmd_thesis,
        "review": cmd_review,
        "replay": cmd_replay,
    }
    try:
        return handlers[args.command](args)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

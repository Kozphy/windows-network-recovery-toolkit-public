"""Replay harness — deterministic policy re-evaluation without side effects."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from platform_core.event_bus import iter_event_lines, validate_schema_version
from platform_core.events import PolicyDecisionPayload
from platform_core.policy.engine import OperatorContext, evaluate


@dataclass
class ReplaySummary:
    """Aggregate counters for dashboards / CLI output."""

    total_events: int
    parse_errors: int
    changed_decisions: int
    newly_blocked_execute: int
    newly_allowed_preview: int


def _norm_pd(obj: dict[str, Any] | None) -> dict[str, Any] | None:
    if obj is None:
        return None
    return {
        "execute_allowed": bool(obj.get("execute_allowed")),
        "preview_allowed": bool(obj.get("preview_allowed")),
        "reason_codes": sorted(obj.get("reason_codes") or []),
        "required_role": str(obj.get("required_role") or "admin"),
        "required_confirmation": obj.get("required_confirmation"),
        "risk_tier": str(obj.get("risk_tier") or "read_only"),
    }


def _telemetry_only(signals: dict[str, Any]) -> dict[str, Any]:
    tele = dict(signals)
    for k in (
        "remediation_action",
        "recommended_action",
        "simulated_operator_role",
        "operator_role",
        "simulated_surface",
    ):
        tele.pop(k, None)
    return tele


def accumulate_replay_counters(
    records: Iterable[dict[str, Any]], *, parse_errors: int = 0
) -> ReplaySummary:
    """Compare embedded ``policy_decision`` vs recomputed gates for streamed records."""

    total = 0
    changed = 0
    newly_blocked = 0
    newly_preview = 0
    pe = parse_errors

    for raw in records:
        ok, _err = validate_schema_version(raw)
        if not ok:
            pe += 1
            continue

        signals = raw.get("signals") or {}
        if not isinstance(signals, dict):
            continue

        action = signals.get("remediation_action") or signals.get("recommended_action")
        if not action:
            continue

        role_any = (
            signals.get("simulated_operator_role") or signals.get("operator_role") or "operator"
        )
        surface_any = signals.get("simulated_surface") or "api"
        if role_any not in ("viewer", "operator", "admin", "security_auditor"):
            role_any = "operator"
        if surface_any not in ("api", "cli", "dashboard"):
            surface_any = "api"

        ctx = OperatorContext(role=role_any, surface=surface_any)  # type: ignore[arg-type]
        gate = evaluate(_telemetry_only(signals), action, ctx)
        new_blob = PolicyDecisionPayload(
            execute_allowed=gate.execute_allowed,
            preview_allowed=gate.preview_allowed,
            reason_codes=gate.reason_codes,
            required_role=gate.required_role,
            required_confirmation=gate.required_confirmation,
            risk_tier=gate.risk_tier,
        ).model_dump()

        total += 1
        prev = raw.get("policy_decision")
        prev_n = _norm_pd(prev if isinstance(prev, dict) else None)
        new_n = _norm_pd(new_blob)

        if prev_n is not None and new_n != prev_n:
            changed += 1
        if prev_n is not None:
            if prev_n.get("execute_allowed") and not new_n.get("execute_allowed"):
                newly_blocked += 1
            if not prev_n.get("preview_allowed") and new_n.get("preview_allowed"):
                newly_preview += 1

    return ReplaySummary(
        total_events=total,
        parse_errors=pe,
        changed_decisions=changed,
        newly_blocked_execute=newly_blocked,
        newly_allowed_preview=newly_preview,
    )


def run_replay(path: Path) -> ReplaySummary:
    """Load JSONL from ``path`` and replay eligible rows."""

    parse_errors = 0

    if path.suffix.lower() == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        seq = raw if isinstance(raw, list) else [raw]
        return accumulate_replay_counters(seq, parse_errors=0)

    def on_err(_idx: int, detail: str) -> None:
        nonlocal parse_errors
        parse_errors += 1

    rows = iter_event_lines(path, on_error=on_err)
    return accumulate_replay_counters(rows, parse_errors=parse_errors)


def summarize_inline(events: list[dict[str, Any]]) -> ReplaySummary:
    """API helper for `/platform/replay/preview`."""

    return accumulate_replay_counters(events)


def main(argv: list[str] | None = None) -> int:
    """CLI entry used by ``python -m platform_core.replay``."""

    parser = argparse.ArgumentParser(
        description="Replay normalized events against policy gates (read-only)."
    )
    parser.add_argument(
        "--input", type=Path, required=True, help="Path to normalized_events JSONL."
    )
    parser.add_argument("--json", action="store_true", help="Emit structured JSON summary.")
    args = parser.parse_args(argv)

    summary = run_replay(args.input)
    if args.json:
        print(json.dumps(summary.__dict__, indent=2))
    else:
        print("Replay summary (read-only)")
        for k, v in summary.__dict__.items():
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

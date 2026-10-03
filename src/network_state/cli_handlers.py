"""Argparse entrypoints for ``python -m src network-state …``."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

from ..proxy_guard.owner import attribution_payload
from ..proxy_guard.parser import parse_proxy_server
from ..proxy_guard.rollback import execute_known_good_proxy_restore
from ..proxy_guard.snapshot_capture import capture_proxy_snapshot
from .audit import append_restore_audit
from .diff_engine import drift_bundle
from .events import emit_network_state_event
from .evidence_import import append_evidence_rows, parse_procmon_like_csv
from .paths import evidence_jsonl as evidence_path
from .paths import policy_json
from .paths import report_json as report_json_path
from .paths import report_txt as report_txt_path
from .policy import NetworkStatePolicy
from .report import build_network_state_report
from .snapshot_store import (
    append_snapshot,
    get_latest_named,
    list_profile_summaries,
    load_default_record,
    snapshot_from_record,
    write_default_profile,
)

RESTORE_CONFIRM = "RESTORE_NETWORK_STATE"


def _repo(args: Namespace) -> Path:
    ex = getattr(args, "repo_root", None)
    if ex:
        return Path(ex).resolve()
    return Path(__file__).resolve().parents[2]


def _win_ok() -> bool:
    if platform.system() != "Windows":
        print("network-state: live capture requires Windows.", file=sys.stderr)
        return False
    return True


def _optional_attribution(proxy_server: str | None, run: Any) -> dict[str, Any]:
    """Best-effort localhost listener mapping — **heuristic**, not proof."""

    parsed = parse_proxy_server(proxy_server)
    port = parsed.localhost_port or parsed.http_localhost_port or parsed.https_localhost_port
    if port is None:
        return {}
    try:
        return dict(attribution_payload(int(port), run=run))
    except (OSError, RuntimeError, TypeError, ValueError):
        return {"notes": ["attribution_unavailable"]}


def cmd_network_state_snapshot_save(args: Namespace) -> int:
    """Run the network state snapshot save command handler.

    Args:
        args: Parsed command-line arguments supplied by argparse.

    Returns:
        Integer process exit code or status value.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    if not _win_ok():
        return 2
    repo = _repo(args)
    name = str(getattr(args, "snapshot_name", "")).strip()
    if not name:
        print("--name required", file=sys.stderr)
        return 2
    snap = capture_proxy_snapshot(run=subprocess.run)
    row = append_snapshot(repo, name=name, snapshot=snap)
    emit_network_state_event(
        repo, "snapshot_saved", {"name": name, "risk_summary": row.get("risk_summary")}
    )
    print(json.dumps(row, indent=2, ensure_ascii=False))
    return 0


def cmd_network_state_snapshot_list(args: Namespace) -> int:
    """Run the network state snapshot list command handler.

    Args:
        args: Parsed command-line arguments supplied by argparse.

    Returns:
        Integer process exit code or status value.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    repo = _repo(args)
    print(json.dumps({"profiles": list_profile_summaries(repo)}, indent=2, ensure_ascii=False))
    return 0


def cmd_network_state_snapshot_show(args: Namespace) -> int:
    """Run the network state snapshot show command handler.

    Args:
        args: Parsed command-line arguments supplied by argparse.

    Returns:
        Integer process exit code or status value.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    repo = _repo(args)
    name = str(getattr(args, "snapshot_name", "")).strip()
    rec = get_latest_named(repo, name)
    if not rec:
        print(f"Unknown profile {name!r}", file=sys.stderr)
        return 1
    print(json.dumps(rec, indent=2, ensure_ascii=False))
    return 0


def cmd_network_state_snapshot_set_default(args: Namespace) -> int:
    """Run the network state snapshot set default command handler.

    Args:
        args: Parsed command-line arguments supplied by argparse.

    Returns:
        Integer process exit code or status value.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    repo = _repo(args)
    name = str(getattr(args, "snapshot_name", "")).strip()
    try:
        path = write_default_profile(repo, name=name)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    emit_network_state_event(repo, "snapshot_saved", {"default_set": True, "name": name})
    print(json.dumps({"default_profile_path": str(path), "name": name}, indent=2))
    return 0


def _load_policy(repo: Path) -> NetworkStatePolicy:
    return NetworkStatePolicy.from_file(policy_json(repo))


def _run_diff(
    repo: Path,
    saved: Any,
    *,
    label: str,
    as_json: bool,
    run=subprocess.run,
) -> dict[str, Any]:
    if saved is None:
        raise ValueError("baseline missing")
    cur = capture_proxy_snapshot(run=run)
    attr = _optional_attribution(cur.proxy_server, run)
    policy = _load_policy(repo)
    bundle = drift_bundle(saved, cur, policy=policy, attribution_heuristic=attr)
    bundle["baseline_label"] = label
    bundle["attribution_sample"] = attr
    if bundle.get("changed_fields"):
        emit_network_state_event(
            repo,
            "drift_detected",
            {
                "baseline": label,
                "suspicious_cases": bundle.get("suspicious_cases"),
                "changed_field_count": len(bundle.get("changed_fields") or {}),
            },
        )
    if bundle.get("policy"):
        emit_network_state_event(repo, "policy_decision", dict(bundle["policy"]))
    return bundle


def cmd_network_state_diff(args: Namespace) -> int:
    """Run the network state diff command handler.

    Args:
        args: Parsed command-line arguments supplied by argparse.

    Returns:
        Integer process exit code or status value.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    if not _win_ok():
        return 2
    repo = _repo(args)
    as_json = bool(getattr(args, "json_out", False))
    use_default = bool(getattr(args, "use_default", False))
    name = str(getattr(args, "snapshot_name", "") or "").strip()
    if use_default:
        rec = load_default_record(repo)
        label = "default"
    elif name:
        rec = get_latest_named(repo, name)
        label = name
    else:
        print("Specify --name or --default", file=sys.stderr)
        return 2
    baseline = snapshot_from_record(rec)
    if baseline is None:
        print("No snapshot baseline found.", file=sys.stderr)
        return 1
    try:
        bundle = _run_diff(repo, baseline, label=label, as_json=as_json, run=subprocess.run)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if as_json:
        print(text)
    else:
        print(text)
    return 0


def cmd_network_state_report(args: Namespace) -> int:
    """Run the network state report command handler.

    Args:
        args: Parsed command-line arguments supplied by argparse.

    Returns:
        Integer process exit code or status value.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    repo = _repo(args)
    since = str(getattr(args, "since", "24h"))
    rep = build_network_state_report(repo, since=since, run=subprocess.run)
    txt = report_txt_path(repo)
    js = report_json_path(repo)
    txt.parent.mkdir(parents=True, exist_ok=True)
    js.write_text(json.dumps(rep, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "Network State Report",
        "====================",
        f"Window: {since}",
        f"Events (approx): {rep['event_totals']['events_ingested']}",
        f"Drift signals: {rep['event_totals']['proxy_drift_signals']}",
        f"Loopback signals: {rep['event_totals']['suspicious_loopback_signals']}",
        f"Default profile: {rep.get('default_profile_name')}",
        f"Drift vs default: {rep.get('drift_vs_default')}",
        "",
        rep.get("recommended_next_action") or "",
    ]
    txt.write_text("\n".join(lines), encoding="utf-8")
    emit_network_state_event(
        repo, "report_generated", {"since": since, "paths": [str(txt), str(js)]}
    )
    if getattr(args, "json_out", False):
        print(json.dumps(rep, indent=2))
    else:
        print(f"Wrote {txt}")
        print(f"Wrote {js}")
    return 0


def cmd_network_state_evidence_import(args: Namespace) -> int:
    """Run the network state evidence import command handler.

    Args:
        args: Parsed command-line arguments supplied by argparse.

    Returns:
        Integer process exit code or status value.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    repo = _repo(args)
    fpath = Path(str(getattr(args, "evidence_file", "")))
    if not fpath.is_file():
        print(f"File not found: {fpath}", file=sys.stderr)
        return 1
    rows = parse_procmon_like_csv(fpath)
    count = append_evidence_rows(repo, rows, source_file=str(fpath.resolve()))
    emit_network_state_event(
        repo,
        "evidence_imported",
        {"source": str(fpath), "normalized_rows": count, "evidence_sink": str(evidence_path(repo))},
    )
    print(json.dumps({"imported_rows": count, "registry_hits": len(rows)}, indent=2))
    return 0


def cmd_network_state_restore(args: Namespace) -> int:
    """Run the network state restore command handler.

    Args:
        args: Parsed command-line arguments supplied by argparse.

    Returns:
        Integer process exit code or status value.

    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    if not _win_ok():
        return 2
    repo = _repo(args)
    name = str(getattr(args, "snapshot_name", "")).strip()
    tgt = snapshot_from_record(get_latest_named(repo, name))
    if tgt is None:
        print(f"Unknown profile {name!r}", file=sys.stderr)
        return 1
    phrase = str(getattr(args, "confirm_phrase", "") or "").strip()
    force_dry = bool(getattr(args, "dry_run", False))
    live = phrase == RESTORE_CONFIRM and not force_dry
    preview = execute_known_good_proxy_restore(
        tgt, dry_run=True, restore_winhttp=True, run=subprocess.run
    )
    append_restore_audit(
        repo, phase="restore_pre_change", name=name, dry_run=not live, preview_or_result=preview
    )

    if not live:
        emit_network_state_event(repo, "rollback_previewed", {"profile": name})
        print(
            "Dry-run / preview — no mutations. Provide --confirm RESTORE_NETWORK_STATE to apply.",
            file=sys.stderr,
        )

    result = execute_known_good_proxy_restore(
        tgt,
        dry_run=not live,
        restore_winhttp=True,
        run=subprocess.run,
    )
    append_restore_audit(
        repo, phase="restore_post_change", name=name, dry_run=not live, preview_or_result=result
    )

    print(json.dumps(result, indent=2, default=str))

    from ..core.jsonl import append_jsonl as aj  # noqa: PLC0415
    from ..core.time_utils import utc_now_iso  # noqa: PLC0415

    aj(
        repo / "logs" / "proxy_guard_actions.jsonl",
        {
            "schema_version": 1,
            "timestamp_utc": utc_now_iso(),
            "action": "network_state_restore",
            "result": "preview" if not live else ("ok" if result.get("success") else "error"),
            "note": json.dumps({"name": name, "live": live})[:2000],
        },
    )

    if live and result.get("success"):
        emit_network_state_event(repo, "rollback_applied", {"profile": name, "success": True})

    return 0 if live and result.get("success") else (0 if not live else 1)

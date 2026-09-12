"""CLI handlers for ``python -m src proxy-snapshot`` (named last-known-good snapshots)."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from typing import Any

from ..core.jsonl import append_jsonl
from ..core.time_utils import utc_now_iso
from .known_good_diff import diff_snapshots
from .known_good_store import (
    append_named_snapshot,
    get_latest_named_record,
    list_snapshot_summaries,
    load_default_record,
    snapshot_from_record,
    summarize_snapshot_risk,
    write_default_config,
)
from .rollback import execute_known_good_proxy_restore
from .snapshot_capture import capture_proxy_snapshot

KNOWN_GOOD_RESTORE_PHRASE = "RESTORE_KNOWN_GOOD_PROXY"


def _repo_root(args: Namespace) -> Path:
    explicit = getattr(args, "repo_root", None)
    if explicit:
        return Path(explicit).resolve()
    return Path(__file__).resolve().parents[2]


def _win_only() -> bool:
    if platform.system() != "Windows":
        print("proxy-snapshot requires Windows for live capture/restore.", file=sys.stderr)
        return False
    return True


def cmd_proxy_snapshot_save(args: Namespace) -> int:
    """Run the proxy snapshot save command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    if not _win_only():
        return 2
    repo = _repo_root(args)
    name = str(getattr(args, "snapshot_name", "") or "").strip()
    if not name:
        print("--name is required.", file=sys.stderr)
        return 2
    run = subprocess.run
    snap = capture_proxy_snapshot(run=run)
    risk = summarize_snapshot_risk(snap)
    row = append_named_snapshot(repo, name=name, snapshot=snap, risk_summary=risk)
    if bool(getattr(args, "as_default", False)):
        write_default_config(repo, row)
        print(f"Default written: {repo / 'config' / 'last_known_good_proxy.json'}")
    print(json.dumps({"saved": row["name"], "saved_at": row["saved_at"], "risk_summary": risk}, indent=2))
    return 0


def cmd_proxy_snapshot_list(args: Namespace) -> int:
    """Run the proxy snapshot list command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    repo = _repo_root(args)
    rows = list_snapshot_summaries(repo)
    default_rec = load_default_record(repo)
    out: dict[str, Any] = {"snapshots": rows, "default_config_present": default_rec is not None}
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


def cmd_proxy_snapshot_show(args: Namespace) -> int:
    """Run the proxy snapshot show command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    repo = _repo_root(args)
    name = str(getattr(args, "snapshot_name", "") or "").strip()
    rec = get_latest_named_record(repo, name)
    if rec is None:
        print(f"No snapshot named {name!r}.", file=sys.stderr)
        return 1
    print(json.dumps(rec, indent=2, ensure_ascii=False))
    return 0


def cmd_proxy_snapshot_diff(args: Namespace) -> int:
    """Run the proxy snapshot diff command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    if not _win_only():
        return 2
    repo = _repo_root(args)
    name = str(getattr(args, "snapshot_name", "") or "").strip()
    rec = get_latest_named_record(repo, name)
    saved = snapshot_from_record(rec)
    if saved is None:
        print(f"No snapshot named {name!r}.", file=sys.stderr)
        return 1
    current = capture_proxy_snapshot(run=subprocess.run)
    diff = diff_snapshots(saved, current)
    print(json.dumps(diff, indent=2, ensure_ascii=False))
    return 0


def cmd_proxy_snapshot_restore(args: Namespace) -> int:
    """Run the proxy snapshot restore command handler.
    
    Args:
        args: Parsed command-line arguments supplied by argparse.
    
    Returns:
        Integer process exit code or status value.
    
    Side effects:
        May write to stdout or stderr and may read fixtures, local reports, or runtime state through the command implementation.
    """
    if not _win_only():
        return 2
    repo = _repo_root(args)
    name = str(getattr(args, "snapshot_name", "") or "").strip()
    rec = get_latest_named_record(repo, name)
    target = snapshot_from_record(rec)
    if target is None:
        print(f"No snapshot named {name!r}.", file=sys.stderr)
        return 1

    phrase = str(getattr(args, "confirm_phrase", "") or "").strip()
    forced_preview = bool(getattr(args, "dry_run", False))
    dry_run = forced_preview or phrase != KNOWN_GOOD_RESTORE_PHRASE
    if dry_run:
        hint = (
            f"Forced by --dry-run. Omit --dry-run and pass --confirm {KNOWN_GOOD_RESTORE_PHRASE} to apply."
            if forced_preview and phrase == KNOWN_GOOD_RESTORE_PHRASE
            else f"Pass --confirm {KNOWN_GOOD_RESTORE_PHRASE} to apply."
        )
        print(f"Dry-run preview only (no mutations). {hint}", file=sys.stderr)

    result = execute_known_good_proxy_restore(
        target,
        dry_run=dry_run,
        restore_winhttp=True,
        run=subprocess.run,
    )
    actions_path = repo / "logs" / "proxy_guard_actions.jsonl"
    append_jsonl(
        actions_path,
        {
            "schema_version": 1,
            "timestamp_utc": utc_now_iso(),
            "action": "proxy_known_good_restore",
            "result": "dry_run_preview"
            if dry_run
            else ("ok" if result.get("success") else "partial_or_error"),
            "note": json.dumps(
                {"name": name, "dry_run": dry_run, "success": result.get("success")},
                ensure_ascii=False,
            )[:4000],
        },
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if not dry_run and not result.get("success"):
        return 1
    return 0

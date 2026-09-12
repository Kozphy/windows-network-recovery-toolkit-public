"""Load recent proxy-watch transitions from append-only JSONL."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .audit import proxy_change_audit_jsonl_path


def parse_since_duration(value: str | int | None) -> int:
    """Parse ``30m``, ``2h``, ``3600``, or seconds int into seconds."""
    if value is None:
        return 1800
    if isinstance(value, int):
        return max(1, value)
    text = str(value).strip().lower()
    if text.isdigit():
        return max(1, int(text))
    match = re.fullmatch(r"(\d+)([smhd])", text)
    if not match:
        return 1800
    qty = int(match.group(1))
    unit = match.group(2)
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return max(1, qty * mult)


def _parse_ts(value: str) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        return None


def load_recent_proxy_transitions(
    repo_root: Path,
    *,
    since_seconds: int = 1800,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return ``proxy_change_detected`` rows within the look-back window."""
    path = proxy_change_audit_jsonl_path(repo_root)
    if not path.is_file():
        return []
    cutoff = datetime.now(UTC) - timedelta(seconds=since_seconds)
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                blob = json.loads(line)
            except json.JSONDecodeError:
                continue
            if blob.get("event") != "proxy_change_detected":
                continue
            ts = _parse_ts(str(blob.get("timestamp") or ""))
            if ts is not None and ts < cutoff:
                continue
            rows.append(blob)
    except OSError:
        return []
    return rows[-limit:]


def summarize_transition_row(row: dict[str, Any]) -> str:
    """Human-readable one-line summary for a proxy-watch JSONL row."""
    diff = row.get("diff") or {}
    reason = diff.get("reason")
    if isinstance(reason, str) and reason.strip():
        return reason.strip()
    changed = diff.get("changed_fields") or []
    if changed:
        return f"Changed: {', '.join(str(x) for x in changed)}"
    before = diff.get("before") or {}
    after = diff.get("after") or {}
    parts: list[str] = []
    if before.get("proxy_enable") != after.get("proxy_enable"):
        parts.append(f"ProxyEnable {before.get('proxy_enable')} -> {after.get('proxy_enable')}")
    if before.get("proxy_server") != after.get("proxy_server"):
        parts.append(
            f"ProxyServer {before.get('proxy_server') or '(empty)'} -> "
            f"{after.get('proxy_server') or '(empty)'}"
        )
    if parts:
        return "; ".join(parts)
    risk = diff.get("risk_level")
    if risk:
        return f"Registry drift (risk={risk})"
    return "change detected"


def build_recovery_guidance(
    *,
    proxy_enable: int | None,
    is_localhost_proxy: bool,
    recent_transitions: list[dict[str, Any]],
    port_owner: dict[str, Any] | None,
    active_reverter: dict[str, Any] | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Return situation interpretation and context-aware preview-only recovery steps."""
    enabled = proxy_enable == 1
    flip = active_reverter is not None

    if not enabled and recent_transitions:
        interpretation = (
            "WinINET proxy is currently disabled, but proxy-watch logged recent registry "
            "transitions. This often means a dev tool or reverter script was toggling proxy "
            "earlier — browser issues may have cleared when proxy disabled. If problems "
            "return when proxy re-enables, follow the recovery chain below (preview first)."
        )
    elif enabled and is_localhost_proxy and port_owner:
        interpretation = (
            "Localhost proxy is active with a correlated listener. Browser failures with "
            "working ping/DNS often match this pattern. Use preview commands first; confirm "
            "with typed phrases before any live change."
        )
    elif enabled and is_localhost_proxy:
        interpretation = (
            "Localhost proxy is enabled but no listener owner was resolved — stale registry "
            "or a dead listener port. Consider proxy-disable after preview review."
        )
    elif enabled:
        interpretation = "WinINET proxy is enabled (non-localhost or PAC). Review before disable."
    else:
        interpretation = (
            "WinINET proxy is disabled and WinHTTP reports direct access. If the browser still "
            "fails, the cause may be DNS, TLS, firewall, or browser-only — run broader diagnosis."
        )

    steps: list[str] = []
    if not enabled and not flip:
        steps.extend(
            [
                "python -m src diagnose-live  # full layer check (DNS, TCP, HTTPS, proxy)",
                "python -m src proxy-watch --interval 5  # catch re-enable if it happens again",
            ]
        )
    if flip:
        steps.extend(
            [
                "python -m src proxy-watch-report --tail 20  # review flip-flop pattern",
                "python -m src proxy-investigate --since 30m --json  # export evidence",
                ".\\scripts\\run_proxy_recovery_admin.ps1  # Admin: stop reverter + listener + soak",
            ]
        )
    if enabled or flip:
        steps.extend(
            [
                "python -m src proxy-disable --dry-run  # preview disable (default safe)",
            ]
        )
        if port_owner and port_owner.get("pid") is not None:
            pid = port_owner.get("pid")
            steps.extend(
                [
                    f"python -m src proxy-stop-listener --dry-run  # preview PID {pid}",
                    "python -m src proxy-stop-listener --dry-run false --confirm STOP_PROXY_LISTENER",
                ]
            )
        if flip or enabled:
            steps.extend(
                [
                    "python -m src proxy-stop-reverter --dry-run",
                    "python -m src proxy-disable --dry-run false --confirm DISABLE_WININET_PROXY --soak-minutes 15",
                ]
            )
    steps.append("python -m src proxy-attribution --procmon procmon.csv  # optional writer proof")
    return interpretation, tuple(dict.fromkeys(steps))


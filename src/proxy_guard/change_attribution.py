"""Probabilistic attribution for HKCU proxy drift via listener correlation and lexical heuristics.

Module responsibility:
    Consume structured diff/current-state snapshots plus :mod:`~src.proxy_guard.process_inventory` rows,
    score candidate processes with additive evidence fragments, optionally adjust using policy allow/block
    fragments and Procmon-derived boosts, emit ranked ``candidates`` with explicit ``limitations``.

System placement:
    Invoked immediately after drift detection inside ``proxy-watch`` ahead of audit persistence.

Explicit non-goals:
    **Never** asserts registry-write attribution without external Sysmon/Procmon/EventLog corroboration.

Key invariants:
    Returned ``confidence`` is clamped inclusive ``[0, 1]`` after summing heuristic mass + optional boosts.

Audit Notes:
    ``limitations`` and ``evidence`` strings deliberately remind reviewers that localhost listener parity is
    *necessary-but-not-sufficient* for causality chains.

Failure modes:
    Empty inventories yield zero confidence primary suspects; aggregates still annotate diff-based risk cues.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

_TOOL_NAMES = frozenset(
    {
        "node.exe",
        "electron.exe",
        "code.exe",
        "cursor.exe",
        "clash.exe",
        "v2ray.exe",
        "shadowsocks.exe",
        "mihomo.exe",
        "python.exe",
    },
)

_CMD_HIT = frozenset(
    {
        "proxy",
        "tunnel",
        "socks",
        "http-proxy",
        "mitm",
        "clash",
        "v2ray",
        "cursor",
        "npm",
        "pnpm",
        "yarn",
    },
)

_PARENT_DEV = frozenset({"code.exe", "cursor.exe", "electron.exe", "devenv.exe", "vscode.exe"})


def _score_row(
    row: dict[str, Any],
    *,
    port: int | None,
    listening_pids: set[int],  # owning PIDs for localhost listener correlation
    now_ts: datetime,
    recent_window_seconds: float,
) -> tuple[float, list[str], bool]:
    score = 0.0
    evidence: list[str] = []
    listening_match = False
    pid = row.get("pid")
    if isinstance(pid, int) and pid in listening_pids and port:
        score += 0.45
        evidence.append(f"Process is listening on localhost:{port}")
        listening_match = True

    name = str(row.get("process_name") or "").lower().strip()
    if name.endswith(".exe"):
        nm = name
    else:
        nm = name + ".exe" if name and "." not in name else name
    if nm in _TOOL_NAMES or name in _TOOL_NAMES:
        score += 0.20
        evidence.append(f"Process name resembles developer/proxy toolchain ({name or nm})")

    cmd = str(row.get("command_line") or "").lower()
    if any(hit in cmd for hit in _CMD_HIT):
        score += 0.10
        evidence.append("Command line mentions proxy/dev tunnel keywords")

    parent_name = str(row.get("parent_process_name") or "").lower()
    if parent_name and any(dev in parent_name for dev in _PARENT_DEV):
        score += 0.10
        evidence.append(f"Parent process resembles developer shell ({parent_name})")

    ctime_s = row.get("creation_time_utc")
    if isinstance(ctime_s, str):
        try:
            ts = datetime.fromisoformat(ctime_s.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            age_sec = abs((now_ts - ts.astimezone(UTC)).total_seconds())
            if age_sec <= recent_window_seconds:
                score += 0.15
                evidence.append("Process creation time within recent correlation window")
        except ValueError:
            pass

    return min(score, 1.0), evidence, listening_match


def _merge_listen_owners(inv: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    block = inv.get("localhost_listener_block") or {}
    pid_to_row = {int(r["pid"]): r for r in rows if isinstance(r.get("pid"), int)}
    for ow in block.get("owners") or []:
        if not isinstance(ow, dict):
            continue
        pid = ow.get("pid")
        if not isinstance(pid, int):
            continue
        tgt = pid_to_row.get(pid)
        if tgt is None:
            tgt = {
                "pid": pid,
                "parent_pid": ow.get("parent_pid"),
                "process_name": ow.get("process_name"),
                "executable_path": ow.get("executable_path"),
                "command_line": ow.get("command_line"),
                "creation_time_utc": ow.get("create_time_utc"),
            }
            rows.append(tgt)
            pid_to_row[pid] = tgt
        tgt.setdefault("parent_process_name", ow.get("parent_name"))
        tgt.setdefault("executable_path", tgt.get("executable_path") or ow.get("executable_path"))
        tgt.setdefault("command_line", tgt.get("command_line") or ow.get("command_line"))


def _parent_names_map(rows: list[dict[str, Any]]) -> dict[int, str]:
    out: dict[int, str] = {}
    for r in rows:
        pid = r.get("pid")
        name = r.get("process_name")
        if isinstance(pid, int) and isinstance(name, str):
            out[pid] = name.lower()
    return out


def attribute_proxy_change(
    *,
    proxy_diff: dict[str, Any],
    current_state: dict[str, Any],
    inventory: dict[str, Any],
    policy: dict[str, Any] | None = None,
    evidence_confidence_boost: float = 0.0,
    recent_window_seconds: float = 300.0,
) -> dict[str, Any]:
    """Rank candidate processes correlated with drift details.

    Args:
        proxy_diff: Output structure from :func:`~src.proxy_guard.wininet_change_diff.diff_wininet_states`.
        current_state: Snapshot from :func:`~src.proxy_guard.state.snapshot_wininet_state`.
        inventory: Payload from :func:`~src.proxy_guard.process_inventory.capture_process_inventory`.
        policy: Optional watcher policy with allow/block lists (may adjust narrative only here).
        evidence_confidence_boost: Additional score mass from correlated Sysmon/Procmon imports (0–1 clamps).
        recent_window_seconds: Freshness horizon (seconds) for rewarding recently created processes.

    Returns:
        Dict shaped for JSONL nesting:
            * ``confidence`` — float rounding to 4 decimals after clamping heuristic + boost mass.
            * ``primary_suspect`` — top scoring row summarized or ``None`` when scores are zero/empty.
            * ``candidates`` — capped list (≤12 entries) omitting strictly zero-score non-listeners when possible.
            * ``evidence`` — deduplicated narrative bullets (≤20).
            * ``limitations`` — merged inventory warnings plus honesty caveats (≤12).

    Side effects:
        None—operates on in-memory structures only.

    Raises:
        None.

    Data handling:
        Policy allow/block lists accept case-insensitive substring matching against process name and exe path
        strings; malformed datetimes on ``creation_time_utc`` ignore the recency heuristic for that row only.

    Engineering Notes:
        Allowlisted tooling names mildly **reduce** heuristic mass to bias away from sanctioned VPN binaries;
        blocked tokens **increase** mass—both are pragmatic tuning hooks, not security guarantees.

    Audit Notes:
        Pair ``listening_port_match`` flags with Procmon CSV rows (``proxy-watch --evidence-csv``) when you must
        document process activity adjacent to HKCU mutations.
    """
    pol = policy or {}
    parsed = current_state.get("parsed_proxy_server") or {}
    port = parsed.get("localhost_port")
    port_i = int(port) if isinstance(port, int) or (isinstance(port, str) and str(port).isdigit()) else None

    lp_block = inventory.get("localhost_listener_block") or {}
    warnings = list(inventory.get("collection_warnings") or [])
    listening_pids: set[int] = set()
    for pid in inventory.get("listening_pids") or []:
        if isinstance(pid, int):
            listening_pids.add(pid)
    for ow in lp_block.get("owners") or []:
        if isinstance(ow, dict) and isinstance(ow.get("pid"), int):
            listening_pids.add(int(ow["pid"]))

    rows: list[dict[str, Any]] = list(inventory.get("process_rows") or [])
    _merge_listen_owners(inventory, rows)
    pmap = _parent_names_map(rows)
    now_ts = datetime.now(UTC)

    enriched: list[dict[str, Any]] = []
    for r in rows:
        rr = dict(r)
        ppid = rr.get("parent_pid")
        if isinstance(ppid, int):
            rr["parent_process_name"] = rr.get("parent_process_name") or pmap.get(ppid, "")
        enriched.append(rr)

    scored: list[tuple[float, dict[str, Any], list[str], bool]] = []
    for r in enriched:
        s, ev, lm = _score_row(
            r,
            port=port_i,
            listening_pids=listening_pids,
            now_ts=now_ts,
            recent_window_seconds=recent_window_seconds,
        )

        allow_names = [str(x).lower() for x in (pol.get("allowed_process_names") or []) if isinstance(x, str)]
        block_names = [str(x).lower() for x in (pol.get("blocked_process_names") or []) if isinstance(x, str)]
        proc_l = str(r.get("process_name") or "").lower()
        exe_l = str(r.get("executable_path") or "").lower()
        if allow_names and any(a in proc_l or a in exe_l for a in allow_names):
            s = max(0.0, s - 0.08)
            ev.append("Process matches operator allowlisted name/path segment")
        if block_names and any(b in proc_l or b in exe_l for b in block_names):
            s = min(s + 0.12, 1.0)
            ev.append("Process matches denylisted heuristic token")

        scored.append((s, r, ev, lm))

    scored.sort(key=lambda t: t[0], reverse=True)

    candidates: list[dict[str, Any]] = []
    for s, row, ev, lm in scored[:12]:
        if s <= 0 and not lm:
            continue
        pid = row.get("pid")
        candidates.append(
            {
                "pid": pid,
                "name": row.get("process_name"),
                "exe": row.get("executable_path"),
                "cmdline": row.get("command_line"),
                "listening_port_match": lm,
                "parent_pid": row.get("parent_pid"),
                "parent_name": row.get("parent_process_name"),
                "score_component": round(s, 4),
                "notes": ev,
            },
        )

    base_conf = scored[0][0] if scored else 0.0
    total = min(base_conf + max(evidence_confidence_boost, 0.0), 1.0)

    primary_block: dict[str, Any] | None = None
    if scored and scored[0][0] > 0:
        s, row, ev, lm = scored[0]
        primary_block = {
            "pid": row.get("pid"),
            "name": row.get("process_name"),
            "exe": row.get("executable_path"),
            "cmdline": row.get("command_line"),
            "listening_port_match": lm,
            "parent_pid": row.get("parent_pid"),
            "parent_name": row.get("parent_process_name"),
        }

    aggregated_evidence: list[str] = []
    parsed_raw = parsed.get("raw")
    if port_i:
        aggregated_evidence.append(f"ProxyServer parses to localhost port {port_i}")
    if parsed_raw:
        aggregated_evidence.append("ProxyServer raw value changed within diff window")

    aggregated_evidence.extend(scored[0][2] if scored else [])
    if proxy_diff.get("risk_level") == "high":
        aggregated_evidence.append("Diff classifier marked risk HIGH")
    aggregated_evidence.append("Registry write attribution requires Sysmon/Procmon/EventLog correlation for proof")

    limitations = warnings + [
        "Attribution is probabilistic correlation — not cryptographic proof of registry writer PID",
        "Without Sysmon EventID 13 (or Procmon registry filters) write-source remains unknown",
    ]

    allow_paths = pol.get("allowed_exe_paths") or []
    _ = allow_paths

    return {
        "confidence": round(total, 4),
        "primary_suspect": primary_block,
        "candidates": candidates,
        "evidence": list(dict.fromkeys(aggregated_evidence))[:20],
        "limitations": limitations[:12],
    }

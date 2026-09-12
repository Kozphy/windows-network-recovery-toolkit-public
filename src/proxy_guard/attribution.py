"""Best-effort process context for Proxy Guard — policy attribution + heuristic pipeline snapshots.

Heuristic attribution uses optional ``psutil`` only (no WMI/subprocess for the pipeline path).
Terminology stays non-accusatory: ``candidate_actor``, ``best-effort attribution only``.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable, Sequence
from typing import Any

from .models import (
    ActorCandidate,
    AttributionResult,
    HeuristicAttributionConfidence,
    HeuristicAttributionMethod,
    HeuristicPipelineAttribution,
    ProcessIdentity,
)

_BASELINE_ATTRIBUTION_NOTES = (
    "best-effort attribution only",
    "registry polling cannot prove exact writer process",
)

# General keyword hits (+20 each) — substring match on lowercased name/exe/cmdline.
_GENERAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "proxy",
        "vpn",
        "tunnel",
        "clash",
        "v2ray",
        "shadowsocks",
        "fiddler",
        "charles",
        "mitm",
        "node",
        "npm",
        "python",
        "java",
        "electron",
        "cursor",
        "code",
    },
)

# Higher-signal tooling (+40 each); also emits ``network_proxy_tool:{kw}`` reasons.
_HIGH_RISK_KEYWORDS: frozenset[str] = frozenset(
    {
        "clash",
        "v2ray",
        "shadowsocks",
        "fiddler",
        "charles",
        "vpn",
        "tunnel",
        "mitm",
    },
)


def collect_process_snapshot() -> list[dict[str, Any]]:
    """Enumerate running processes via optional ``psutil`` (metadata only).

    Returns:
        Normalized rows with keys ``pid``, ``name``, ``exe``, ``cmdline`` (``str``), ``ppid``,
        ``create_time`` (``float`` epoch or omitted). Empty when ``psutil`` is unavailable or every
        row errors (AccessDenied, etc.).
    """

    try:
        import psutil  # type: ignore[import-not-found]
        from psutil import Error as PsutilError  # noqa: N812
    except ImportError:
        return []

    out: list[dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline", "ppid", "create_time"]):
        try:
            info = proc.info
            pid = info.get("pid")
            if not isinstance(pid, int):
                continue
            name = info.get("name")
            exe = info.get("exe")
            ppid_raw = info.get("ppid")
            ppid = int(ppid_raw) if isinstance(ppid_raw, int) else None
            cmd = info.get("cmdline")
            if isinstance(cmd, (list, tuple)):
                try:
                    cmdline_s = subprocess.list2cmdline(list(cmd))
                except (TypeError, ValueError):
                    cmdline_s = " ".join(str(x) for x in cmd)
            elif isinstance(cmd, str):
                cmdline_s = cmd
            else:
                cmdline_s = ""

            row: dict[str, Any] = {
                "pid": pid,
                "name": str(name) if isinstance(name, str) else "",
                "exe": str(exe) if isinstance(exe, str) else "",
                "cmdline": cmdline_s,
                "ppid": ppid,
            }
            ct = info.get("create_time")
            if isinstance(ct, (int, float)):
                row["create_time"] = float(ct)
            out.append(row)
        except PsutilError:  # type: ignore[misc]
            continue
        except OSError:
            continue
        except ValueError:
            continue
        except TypeError:
            continue
        except AttributeError:
            continue
    return out


def _combined_proc_text(proc: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("name", "exe", "cmdline"):
        val = proc.get(key)
        if isinstance(val, str) and val:
            parts.append(val.lower())
    return " ".join(parts)


def score_process(
    proc: dict[str, Any],
    *,
    now: float,
    recent_window_seconds: int = 30,
) -> tuple[int, list[str]]:
    """Return capped heuristic score [0, 100] and explicit machine-readable reasons."""

    text = _combined_proc_text(proc)
    score = 0
    reasons_raw: list[str] = []

    for kw in sorted(_HIGH_RISK_KEYWORDS):
        if kw in text:
            score += 40
            reasons_raw.append(f"matched_keyword:{kw}")
            reasons_raw.append(f"network_proxy_tool:{kw}")

    for kw in sorted(_GENERAL_KEYWORDS - _HIGH_RISK_KEYWORDS):
        if kw in text:
            score += 20
            reasons_raw.append(f"matched_keyword:{kw}")

    ct = proc.get("create_time")
    if isinstance(ct, (int, float)):
        try:
            if now - float(ct) >= 0 and (now - float(ct)) <= float(recent_window_seconds):
                score += 10
                reasons_raw.append("recently_started_process")
        except (TypeError, ValueError, OSError):
            pass

    score = min(score, 100)
    deduped = sorted(set(reasons_raw))
    return score, deduped


def _confidence_for_score(score: int) -> HeuristicAttributionConfidence:
    if score >= 80:
        return "medium"
    if score >= 40:
        return "low"
    return "unknown"


def attribute_proxy_change(
    process_snapshot: list[dict[str, Any]] | None = None,
    *,
    now: float | None = None,
    recent_window_seconds: int = 30,
) -> HeuristicPipelineAttribution:
    """Select a single ``candidate_actor`` via heuristic scoring (never proves registry writer).

    Args:
        process_snapshot: Optional pre-built rows (deterministic tests). ``None`` triggers
            :func:`collect_process_snapshot`.
        now: Unix timestamp for ``recently_started_process`` heuristic; defaults to ``time.time()``.
        recent_window_seconds: Windows for recency bonus.
    """

    notes = _BASELINE_ATTRIBUTION_NOTES
    ts = float(now) if now is not None else time.time()

    if process_snapshot is not None:
        snap = process_snapshot
        method: HeuristicAttributionMethod = "psutil_snapshot_heuristic"
    else:
        snap = collect_process_snapshot()
        method = "psutil_snapshot_heuristic" if snap else "unavailable"

    if not snap:
        return HeuristicPipelineAttribution(
            candidate_actor=None,
            attribution_confidence="unknown",
            attribution_method="unavailable",
            attribution_notes=notes,
        )

    best_proc: dict[str, Any] | None = None
    best_score = 0
    best_reasons: list[str] = []

    for proc in snap:
        if not isinstance(proc, dict):
            continue
        try:
            sc, rsn = score_process(proc, now=ts, recent_window_seconds=recent_window_seconds)
        except Exception:
            continue
        pid = proc.get("pid")
        pid_i = int(pid) if isinstance(pid, int) else 0
        best_pid = int(best_proc["pid"]) if isinstance(best_proc, dict) and isinstance(best_proc.get("pid"), int) else 1_000_000_000
        if sc > best_score or (sc == best_score and sc > 0 and pid_i < best_pid):
            best_score = sc
            best_reasons = rsn
            best_proc = proc

    if best_proc is None or best_score <= 0:
        return HeuristicPipelineAttribution(
            candidate_actor=None,
            attribution_confidence="unknown",
            attribution_method=method,
            attribution_notes=notes,
        )

    pid = best_proc.get("pid")
    pid_i = int(pid) if isinstance(pid, int) else -1
    name = str(best_proc.get("name") or "")
    exe = best_proc.get("exe")
    exe_s = str(exe) if isinstance(exe, str) and exe.strip() else None
    ppid = best_proc.get("ppid")
    ppid_i = int(ppid) if isinstance(ppid, int) else None
    cmdline = best_proc.get("cmdline")
    cmd_s = str(cmdline) if isinstance(cmdline, str) else None

    candidate = ActorCandidate(
        pid=pid_i,
        process_name=name,
        process_path=exe_s,
        parent_pid=ppid_i,
        command_line=cmd_s,
        score=best_score,
        reasons=tuple(best_reasons),
    )
    return HeuristicPipelineAttribution(
        candidate_actor=candidate,
        attribution_confidence=_confidence_for_score(best_score),
        attribution_method=method,
        attribution_notes=notes,
    )


def heuristic_attribution_to_audit_dict(h: HeuristicPipelineAttribution) -> dict[str, Any]:
    """JSON ``attribute`` subtree for schema_version ``1`` pipeline rows."""

    return h.to_jsonable()


# --- WMI / listen-owner supplement for *policy-layer* AttributionResult only ---


def wmi_like_process_snapshot(
    *,
    run: Callable[..., Any] = subprocess.run,
    timeout_seconds: float = 6.0,
) -> list[dict[str, Any]]:
    """Return recent process rows via ``Get-CimInstance`` (falls back to empty)."""

    cmd = (
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        (
            "Get-CimInstance Win32_Process | Select-Object ProcessId,"
            "ParentProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress"
        ),
    )
    try:
        proc = run(cmd, capture_output=True, text=True, shell=False, timeout=timeout_seconds)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    blob = getattr(proc, "stdout", "") or ""
    blob = blob.strip()
    if not blob:
        return []
    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError:
        return []
    rows: list[dict[str, Any]]
    if isinstance(parsed, dict):
        rows = [parsed]
    elif isinstance(parsed, list):
        rows = [x for x in parsed if isinstance(x, dict)]
    else:
        return []
    return rows


def _row_text(proc: dict[str, Any]) -> str:
    parts = []
    for key in ("Name", "ExecutablePath", "CommandLine"):
        val = proc.get(key)
        if isinstance(val, str):
            parts.append(val.lower())
    return " ".join(parts)


def pick_heuristic_rows(process_rows: Sequence[dict[str, Any]], *, max_rows: int = 5) -> list[dict[str, Any]]:
    """Cheap substring scan against WMI-shaped rows for policy-layer fallback."""

    tokens = tuple(sorted(set(_GENERAL_KEYWORDS)))
    scored: list[tuple[int, dict[str, Any]]] = []
    for proc in process_rows:
        text = _row_text(proc)
        score_count = sum(1 for tok in tokens if tok in text)
        if score_count:
            scored.append((score_count, proc))
    scored.sort(key=lambda x: (-x[0], str(x[1].get("ProcessId") or "")))
    return [row for _, row in scored[:max_rows]]


def attribution_from_heuristic_rows(rows: Sequence[dict[str, Any]]) -> AttributionResult | None:
    """Build synthetic :class:`AttributionResult` for whitelist policy correlation only."""

    if not rows:
        return None
    top = rows[0]
    pid_raw = top.get("ProcessId")
    ppid_raw = top.get("ParentProcessId")
    pid = int(pid_raw) if isinstance(pid_raw, int) else (int(pid_raw) if isinstance(pid_raw, str) and pid_raw.isdigit() else None)
    ppid: int | None = None
    if ppid_raw is not None:
        if isinstance(ppid_raw, int):
            ppid = ppid_raw
        elif isinstance(ppid_raw, str) and ppid_raw.isdigit():
            ppid = int(ppid_raw)
    exe = top.get("ExecutablePath") if isinstance(top.get("ExecutablePath"), str) else None
    name = top.get("Name") if isinstance(top.get("Name"), str) else None
    cmdline = top.get("CommandLine") if isinstance(top.get("CommandLine"), str) else None

    proc = ProcessIdentity(
        pid=pid,
        ppid=ppid,
        exe=exe,
        name=name,
        cmdline=cmdline,
        create_time_utc=None,
        user=None,
        source="best_effort_recent_snapshot",
    )
    return AttributionResult(
        mode="best_effort_process_snapshot",
        confidence="low",
        process=proc,
        evidence=("heuristic_recent_process_lexicon_candidate_not_writer_proof",),
        limitations=(
            "best_effort_attribution_candidate_only",
            "registry_poll_cannot_prove_writer",
        ),
    )


def enhance_attribution_for_pipeline(
    *,
    base: AttributionResult,
    owners_payload: dict[str, Any],
    run: Callable[..., Any],
) -> tuple[AttributionResult, bool]:
    """Prefer ``base``; when empty, correlate WMI heuristic rows (policy path only)."""

    if base.process is not None:
        return base, False

    extras = pick_heuristic_rows(wmi_like_process_snapshot(run=run))
    heur = attribution_from_heuristic_rows(extras)
    if heur is not None:
        ev = tuple(dict.fromkeys(heur.evidence + tuple(owners_payload.get("notes") or ())))
        lim = tuple(dict.fromkeys(heur.limitations + ("wmi_lexicon_fallback",)))
        merged = AttributionResult(
            mode=heur.mode,
            confidence="low",
            process=heur.process,
            evidence=ev,
            limitations=lim,
        )
        return merged, True
    return base, False

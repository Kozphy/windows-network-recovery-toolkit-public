"""HKCU WinINET repair snapshots for rollback (`logs/proxy_snapshots.jsonl`).

Captures dword/string values **with presence** so rollback can restore both values and absent keys
via ``reg add`` / ``reg delete`` (no arbitrary shell).

Safety:
    Callers must require typed confirmation before applying restore argv lists.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .registry import read_proxy_registry_with_presence
from .remediation import INTERNET_SETTINGS_KEY

_SNAPSHOT_CONFIRMATION_PHRASE = "RESTORE_WININET"


@dataclass(frozen=True)
class WinInetCapturedState:
    """Normalized capture used for rollback planning."""

    snapshot_id: str
    captured_at_utc: str
    values: dict[str, Any]
    presence: dict[str, bool]

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "schema_version": "1",
            "kind": "wininet_hkcu_capture",
            "snapshot_id": self.snapshot_id,
            "captured_at_utc": self.captured_at_utc,
            "values": dict(self.values),
            "presence": dict(self.presence),
        }


def snapshot_confirmation_phrase() -> str:
    """Typed phrase required before applying rollback mutations."""
    return _SNAPSHOT_CONFIRMATION_PHRASE


def capture_wininet_snapshot(
    *,
    run: Callable[..., Any],
    snapshot_id: str | None = None,
) -> WinInetCapturedState:
    """Read HKCU WinINET proxy values plus per-value existence flags.

    Args:
        run: Inject ``subprocess.run`` (tests) or default OS execution.
        snapshot_id: Optional stable id (defaults to UUID4).

    Returns:
        :class:`WinInetCapturedState` suitable for JSONL + rollback argv synthesis.
    """
    snap, presence = read_proxy_registry_with_presence(run=run)
    sid = snapshot_id or str(uuid.uuid4())
    ts = datetime.now(UTC).isoformat()
    values: dict[str, Any] = {
        "ProxyEnable": snap.proxy_enable,
        "ProxyServer": snap.proxy_server,
        "AutoConfigURL": snap.auto_config_url,
        "AutoDetect": snap.auto_detect,
        "ProxyOverride": snap.proxy_override,
    }
    keys = ("ProxyEnable", "ProxyServer", "AutoConfigURL", "AutoDetect", "ProxyOverride")
    pres = {k: bool(presence.get(k, False)) for k in keys}
    return WinInetCapturedState(snapshot_id=sid, captured_at_utc=ts, values=values, presence=pres)


def build_rollback_plan(state: WinInetCapturedState | dict[str, Any]) -> dict[str, Any]:
    """Human-readable rollback plan alongside argv echo strings (still reg-only)."""
    if isinstance(state, WinInetCapturedState):
        vals = state.values
        pres = state.presence
        sid = state.snapshot_id
    else:
        vals = dict(state.get("values") or {})
        pres = dict(state.get("presence") or {})
        sid = str(state.get("snapshot_id") or "")
    steps: list[str] = []
    for name in ("ProxyOverride", "AutoConfigURL", "ProxyServer", "AutoDetect", "ProxyEnable"):
        if not pres.get(name, False):
            steps.append(f'reg delete "{INTERNET_SETTINGS_KEY}" /v {name} /f  # restore absence')
            continue
        v = vals.get(name)
        if name in {"ProxyEnable", "AutoDetect"}:
            dword = 0 if v is None else int(v)
            steps.append(
                f'reg add "{INTERNET_SETTINGS_KEY}" /v {name} /t REG_DWORD /d {dword} /f',
            )
        else:
            s = "" if v is None else str(v)
            steps.append(f'reg add "{INTERNET_SETTINGS_KEY}" /v {name} /t REG_SZ /d "{s}" /f')
    return {
        "type": "wininet_hkcu_reg_argv",
        "snapshot_id": sid,
        "summary": "Restore HKCU WinINET values via reg.exe (no shell); order is ProxyOverride→…→ProxyEnable.",
        "steps": steps,
    }


def build_restore_reg_argv(
    state: WinInetCapturedState | dict[str, Any],
) -> tuple[tuple[str, ...], ...]:
    """Synthesize ordered ``reg.exe`` argument vectors that restore captured state."""
    if isinstance(state, WinInetCapturedState):
        vals = state.values
        pres = state.presence
    else:
        vals = dict(state.get("values") or {})
        pres = dict(state.get("presence") or {})

    argv_list: list[tuple[str, ...]] = []
    key = INTERNET_SETTINGS_KEY
    # Deterministic ordering: strings first (dependent apps may read multiples), dw last.
    for name in ("ProxyOverride", "AutoConfigURL", "ProxyServer", "AutoDetect", "ProxyEnable"):
        if not pres.get(name, False):
            argv_list.append(("reg", "delete", key, "/v", name, "/f"))
            continue
        v = vals.get(name)
        if name in {"ProxyEnable", "AutoDetect"}:
            dword = 0 if v is None else int(v)
            argv_list.append(
                ("reg", "add", key, "/v", name, "/t", "REG_DWORD", "/d", str(dword), "/f")
            )
        else:
            s = "" if v is None else str(v)
            argv_list.append(("reg", "add", key, "/v", name, "/t", "REG_SZ", "/d", s, "/f"))
    return tuple(argv_list)


def append_proxy_snapshots_jsonl(repo_root: Path, record: dict[str, Any]) -> Path:
    """Append one snapshot record under ``logs/proxy_snapshots.jsonl``."""
    path = repo_root / "logs" / "proxy_snapshots.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return path


def load_snapshot_record_by_id(path: Path, snapshot_id: str) -> dict[str, Any] | None:
    """Scan JSONL from top to bottom; last matching ``snapshot_id`` wins."""
    if not path.is_file():
        return None
    found: dict[str, Any] | None = None
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("snapshot_id") == snapshot_id:
                found = obj
    return found


def merge_snapshot_payload(
    capture: WinInetCapturedState, rollback_plan: dict[str, Any]
) -> dict[str, Any]:
    """Persist JSONL row including embedded rollback plan for offline review."""
    base = capture.to_jsonable()
    base["rollback_plan"] = rollback_plan
    return base

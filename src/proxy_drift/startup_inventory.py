"""Targeted Windows startup inventory (no full profile recursion)."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.logging.audit import append_jsonl

_SCHEMA = "startup_inventory.v1"
_MAX_HASH_BYTES = 10 * 1024 * 1024

_SUSPICIOUS_TOKENS = (
    "node.exe",
    "powershell.exe",
    "cmd.exe",
    "python.exe",
    "electron",
    "vpn",
    "hide.me",
    "openvpn",
    "wireguard",
    "127.0.0.1",
    "localhost",
    "proxy",
    "guardian",
    "startup",
    "wnrt",
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _suspicious_indicators(command: str) -> list[str]:
    lower = (command or "").lower()
    return [tok for tok in _SUSPICIOUS_TOKENS if tok in lower]


def _file_hash(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > _MAX_HASH_BYTES:
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _signer_info(path: Path, run: Callable[..., Any]) -> str | None:
    if platform.system() != "Windows" or not path.is_file():
        return None
    ps = (
        f"$s=Get-AuthenticodeSignature -LiteralPath '{path}' -ErrorAction SilentlyContinue; "
        f"if ($s) {{ $s.SignerCertificate.Subject }}"
    )
    try:
        proc = run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=20,
            shell=False,
        )
        text = (proc.stdout or "").strip()
        return text or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _resolve_command_path(command: str) -> Path | None:
    text = (command or "").strip().strip('"')
    if not text:
        return None
    token = text.split()[0].strip('"')
    candidate = Path(token)
    if candidate.is_file():
        return candidate
    if os.path.isabs(token):
        return candidate if candidate.exists() else None
    return None


def _entry(
    *,
    source_type: str,
    name: str,
    command: str,
    run: Callable[..., Any],
) -> dict[str, Any]:
    path = _resolve_command_path(command)
    exists = path.is_file() if path else False
    return {
        "source_type": source_type,
        "name": name,
        "command": command,
        "path": str(path) if path else "",
        "exists": exists,
        "signer": _signer_info(path, run) if path and exists else None,
        "sha256": _file_hash(path) if path and exists else None,
        "suspicious_indicators": _suspicious_indicators(command),
    }


def _startup_folder_entries(folder: Path, source_type: str, run: Callable[..., Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not folder.is_dir():
        return rows
    for item in sorted(folder.iterdir()):
        if item.suffix.lower() == ".lnk":
            rows.append(
                _entry(source_type=source_type, name=item.stem, command=str(item), run=run)
            )
        elif item.is_file():
            rows.append(
                _entry(source_type=source_type, name=item.name, command=str(item), run=run)
            )
    return rows


def _registry_run_entries(hive: str, subkey: str, source_type: str, run: Callable[..., Any]) -> list[dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    path = f"{hive}\\{subkey}"
    try:
        proc = run(
            ["reg", "query", path],
            capture_output=True,
            text=True,
            timeout=20,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith(path) or "REG_" not in line:
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        name, _typ, value = parts[0], parts[1], parts[2]
        rows.append(_entry(source_type=source_type, name=name, command=value, run=run))
    return rows


def _scheduled_task_entries(run: Callable[..., Any]) -> list[dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    try:
        proc = run(
            ["schtasks", "/query", "/fo", "LIST", "/v"],
            capture_output=True,
            text=True,
            timeout=60,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    rows: list[dict[str, Any]] = []
    name = ""
    command = ""
    for line in (proc.stdout or "").splitlines():
        if line.startswith("TaskName:"):
            if name and command:
                rows.append(
                    _entry(source_type="scheduled_task", name=name, command=command, run=run)
                )
            name = line.split(":", 1)[1].strip()
            command = ""
        elif line.startswith("Task To Run:"):
            command = line.split(":", 1)[1].strip()
    if name and command:
        rows.append(_entry(source_type="scheduled_task", name=name, command=command, run=run))
    return rows


def _wmi_startup_entries(run: Callable[..., Any]) -> list[dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    ps = (
        "Get-CimInstance Win32_StartupCommand | "
        "Select-Object Name, Command, Location, User | ConvertTo-Json -Compress"
    )
    try:
        proc = run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=45,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0 or not (proc.stdout or "").strip():
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    items = data if isinstance(data, list) else [data]
    rows: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        loc = str(item.get("Location") or "wmi_startup")
        rows.append(
            _entry(
                source_type=f"wmi_startup:{loc}",
                name=str(item.get("Name") or ""),
                command=str(item.get("Command") or ""),
                run=run,
            )
        )
    return rows


def collect_startup_inventory(
    *,
    repo_root: Path | None = None,
    audit_path: Path | None = None,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Collect high-signal startup entries without scanning the full user profile."""
    subprocess_run = run if run is not None else subprocess.run
    appdata = Path(os.environ.get("APPDATA", ""))
    program_data = Path(os.environ.get("ProgramData", r"C:\ProgramData"))

    entries: list[dict[str, Any]] = []
    entries.extend(
        _startup_folder_entries(
            appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            "user_startup_folder",
            subprocess_run,
        )
    )
    entries.extend(
        _startup_folder_entries(
            program_data / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            "common_startup_folder",
            subprocess_run,
        )
    )
    entries.extend(
        _registry_run_entries(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion",
            "Run",
            "hkcu_run",
            subprocess_run,
        )
    )
    entries.extend(
        _registry_run_entries(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion",
            "RunOnce",
            "hkcu_runonce",
            subprocess_run,
        )
    )
    entries.extend(
        _registry_run_entries(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion",
            "Run",
            "hklm_run",
            subprocess_run,
        )
    )
    entries.extend(
        _registry_run_entries(
            r"HKLM\Software\Microsoft\Windows\CurrentVersion",
            "RunOnce",
            "hklm_runonce",
            subprocess_run,
        )
    )
    entries.extend(_scheduled_task_entries(subprocess_run))
    entries.extend(_wmi_startup_entries(subprocess_run))

    payload: dict[str, Any] = {
        "schema_version": _SCHEMA,
        "timestamp_utc": _now(),
        "platform": platform.system(),
        "entry_count": len(entries),
        "entries": entries,
        "limitations": [
            "Startup inventory is read-only correlation — not proof of proxy registry writer.",
            "Scheduled task list may be truncated on policy-locked hosts.",
        ],
    }
    if audit_path is not None:
        append_jsonl(audit_path, {"event": "startup_inventory", **payload})
    if repo_root is not None and audit_path is None:
        default_audit = repo_root / "logs" / "startup_inventory.jsonl"
        append_jsonl(default_audit, {"event": "startup_inventory", **payload})
    return payload


def format_startup_table(payload: dict[str, Any]) -> str:
    """Human-readable table for startup inventory."""
    lines = [
        "Startup inventory (targeted — no full profile recursion)",
        f"Entries: {payload.get('entry_count', 0)}",
        "",
        f"{'Source':<22} {'Name':<28} {'Exists':<6} Indicators",
        "-" * 90,
    ]
    for row in payload.get("entries") or []:
        indicators = ",".join(row.get("suspicious_indicators") or []) or "-"
        lines.append(
            f"{str(row.get('source_type','')):<22} "
            f"{str(row.get('name',''))[:27]:<28} "
            f"{str(row.get('exists', False)):<6} "
            f"{indicators}"
        )
    return "\n".join(lines) + "\n"

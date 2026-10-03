"""Gated Edge extension block/restore via HKCU ExtensionSettings policy.

Module responsibility:
    Preview or apply an allowlisted set of Edge extension IDs as
    ``installation_mode: blocked`` under ``HKCU\\SOFTWARE\\Policies\\Microsoft\\Edge``.
    Optional UAC elevation when the Policies key is admin-ACL'd.

System placement:
    CLI: ``edge-extensions-disable`` / ``edge-extensions-restore``.
    Does not mutate Chromium Secure Preferences (HMAC-protected).

Key invariants:
    * Dry-run default; live apply needs typed tokens.
    * Only operator-supplied IDs or named presets — never “disable all”.
    * Does not kill Edge processes unless ``--stop-edge`` is set on apply.

Side effects:
    May write/remove ``ExtensionSettings`` REG_SZ; may spawn elevated PowerShell.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from windows_network_toolkit.audit_store import append_audit_dict
from windows_network_toolkit.browser_blank_screen import edge_user_data_dir
from windows_network_toolkit.safety import CONFIRMATION_TOKENS, DEFAULT_SAFETY_NOTES, is_demo_mode

DISABLE_TOKEN = CONFIRMATION_TOKENS.get(
    "DISABLE_EDGE_EXTENSIONS_VIA_POLICY", "DISABLE_EDGE_EXTENSIONS_VIA_POLICY"
)
RESTORE_TOKEN = CONFIRMATION_TOKENS.get(
    "RESTORE_EDGE_EXTENSIONS_POLICY", "RESTORE_EDGE_EXTENSIONS_POLICY"
)

POLICY_KEY = r"HKCU\SOFTWARE\Policies\Microsoft\Edge"
POLICY_VALUE = "ExtensionSettings"

# Chromium extension id: 32 lowercase letters a-p
_EXT_ID_RE = re.compile(r"^[a-p]{32}$")

# Presets: common Cloudflare-challenge risk extensions (names for operators only).
EXTENSION_PRESETS: dict[str, list[dict[str, str]]] = {
    "cloudflare-risk": [
        {
            "id": "bgnkhhnnamicmpeenaelnjfhikgbkllg",
            "name": "AdGuard AdBlocker",
        },
        {
            "id": "djflhoibgkdhkhhcedjiklpkjnoahfmg",
            "name": "User-Agent Switcher for Chrome",
        },
    ],
}

LIMITATIONS = [
    "Blocks via Edge ExtensionSettings policy only — does not uninstall extensions.",
    "HKCU Policies\\Microsoft\\Edge may require UAC elevation on locked ACLs.",
    "Observation is not proof that an extension caused a Cloudflare loop.",
    "Installed check scans the Default Edge profile only; other profiles are not inspected.",
    *DEFAULT_SAFETY_NOTES,
]


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_extension_ids(raw_ids: list[str]) -> tuple[list[str], list[str]]:
    """Validate and normalize extension IDs.

    Returns:
        ``(valid_ids, invalid_tokens)``.
    """
    valid: list[str] = []
    invalid: list[str] = []
    for raw in raw_ids:
        for part in str(raw).replace(";", ",").split(","):
            eid = part.strip().lower()
            if not eid:
                continue
            if _EXT_ID_RE.fullmatch(eid):
                if eid not in valid:
                    valid.append(eid)
            else:
                invalid.append(part.strip())
    return valid, invalid


def resolve_targets(
    *,
    ids: list[str] | None = None,
    preset: str | None = None,
) -> dict[str, Any]:
    """Resolve preset and/or explicit IDs into a target list."""
    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    errors: list[str] = []

    if preset:
        key = preset.strip().lower()
        rows = EXTENSION_PRESETS.get(key)
        if rows is None:
            errors.append(f"unknown_preset:{preset}")
        else:
            for row in rows:
                eid = row["id"]
                if eid not in seen:
                    seen.add(eid)
                    targets.append(dict(row))

    valid, invalid = normalize_extension_ids(list(ids or []))
    if invalid:
        errors.append(f"invalid_extension_ids:{invalid}")
    for eid in valid:
        if eid not in seen:
            seen.add(eid)
            targets.append({"id": eid, "name": eid})

    return {"targets": targets, "errors": errors}


def installed_extension_ids(user_data_dir: Path | None = None) -> set[str] | None:
    """Return extension IDs installed in the Default Edge profile (read-only).

    Args:
        user_data_dir: Override Edge User Data path (tests).

    Returns:
        Set of valid extension IDs, or ``None`` when the Extensions dir is absent
        or unreadable (unknown — not the same as "none installed").
    """
    ext_dir = (user_data_dir or edge_user_data_dir()) / "Default" / "Extensions"
    if not ext_dir.is_dir():
        return None
    try:
        return {p.name for p in ext_dir.iterdir() if p.is_dir() and _EXT_ID_RE.fullmatch(p.name)}
    except OSError:
        return None


def annotate_installed(
    targets: list[dict[str, str]], installed: set[str] | None
) -> list[dict[str, Any]]:
    """Copy targets with ``installed`` = True/False, or None when unknown."""
    return [
        {**row, "installed": (row["id"] in installed) if installed is not None else None}
        for row in targets
    ]


def build_extension_settings_json(targets: list[dict[str, str]]) -> str:
    """Build Edge ExtensionSettings REG_SZ payload (blocked only)."""
    body = {row["id"]: {"installation_mode": "blocked"} for row in targets}
    return json.dumps(body, separators=(",", ":"), ensure_ascii=False)


def read_extension_settings() -> str | None:
    """Read current ExtensionSettings value, or None if absent/unreadable."""
    if platform.system() != "Windows":
        return None
    try:
        completed = subprocess.run(
            ["reg", "query", POLICY_KEY, "/v", POLICY_VALUE],
            capture_output=True,
            text=True,
            errors="ignore",
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    # REG_SZ line: ExtensionSettings    REG_SZ    {...}
    for line in (completed.stdout or "").splitlines():
        if POLICY_VALUE in line and "REG_SZ" in line:
            parts = line.split("REG_SZ", 1)
            if len(parts) == 2:
                return parts[1].strip() or None
    return None


def write_extension_settings(value: str) -> dict[str, Any]:
    """Write ExtensionSettings without elevation."""
    try:
        completed = subprocess.run(
            ["reg", "add", POLICY_KEY, "/v", POLICY_VALUE, "/t", "REG_SZ", "/d", value, "/f"],
            capture_output=True,
            text=True,
            errors="ignore",
            check=False,
        )
    except OSError as exc:
        return {"ok": False, "error": str(exc)[:200], "elevated": False}
    ok = completed.returncode == 0
    return {
        "ok": ok,
        "returncode": completed.returncode,
        "excerpt": ((completed.stdout or "") + (completed.stderr or ""))[:300],
        "elevated": False,
    }


def delete_extension_settings() -> dict[str, Any]:
    """Delete ExtensionSettings value without elevation."""
    try:
        completed = subprocess.run(
            ["reg", "delete", POLICY_KEY, "/v", POLICY_VALUE, "/f"],
            capture_output=True,
            text=True,
            errors="ignore",
            check=False,
        )
    except OSError as exc:
        return {"ok": False, "error": str(exc)[:200], "elevated": False}
    # exit 1 often means value already absent
    ok = completed.returncode == 0 or "unable to find" in (completed.stderr or "").lower()
    return {
        "ok": ok,
        "returncode": completed.returncode,
        "excerpt": ((completed.stdout or "") + (completed.stderr or ""))[:300],
        "elevated": False,
    }


def _run_elevated_powershell(ps_body: str) -> dict[str, Any]:
    """Spawn UAC-elevated PowerShell with a temp script; return result marker file."""
    marker = Path(tempfile.gettempdir()) / f"wnrt_edge_ext_policy_{os.getpid()}.txt"
    if marker.is_file():
        marker.unlink(missing_ok=True)  # type: ignore[call-arg]
    script = (
        "$ErrorActionPreference = 'Stop'\n"
        f"{ps_body}\n"
        f"'OK' | Out-File -FilePath '{marker.as_posix()}' -Encoding utf8\n"
    )
    script_path = Path(tempfile.gettempdir()) / f"wnrt_edge_ext_policy_{os.getpid()}.ps1"
    script_path.write_text(script, encoding="utf-8")
    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                (
                    f"Start-Process -FilePath powershell.exe -Verb RunAs -Wait "
                    f"-ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{script_path}'"
                ),
            ],
            capture_output=True,
            text=True,
            errors="ignore",
            check=False,
        )
    except OSError as exc:
        return {"ok": False, "error": str(exc)[:200], "elevated": True}
    ok = marker.is_file()
    if marker.is_file():
        marker.unlink(missing_ok=True)  # type: ignore[call-arg]
    try:
        script_path.unlink(missing_ok=True)  # type: ignore[call-arg]
    except OSError:
        pass
    return {
        "ok": ok,
        "returncode": completed.returncode,
        "excerpt": ((completed.stdout or "") + (completed.stderr or ""))[:300],
        "elevated": True,
        "uac_cancelled_or_failed": not ok,
    }


def write_extension_settings_elevated(value: str) -> dict[str, Any]:
    """Write ExtensionSettings with UAC elevation."""
    # Escape single quotes for PowerShell single-quoted string
    esc = value.replace("'", "''")
    body = (
        f"$key = '{POLICY_KEY.replace('HKCU', 'HKCU:')}'\n"
        "if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }\n"
        f"Set-ItemProperty -Path $key -Name '{POLICY_VALUE}' -Value '{esc}' -Type String\n"
    )
    return _run_elevated_powershell(body)


def delete_extension_settings_elevated() -> dict[str, Any]:
    """Remove ExtensionSettings with UAC elevation."""
    body = (
        f"$key = '{POLICY_KEY.replace('HKCU', 'HKCU:')}'\n"
        f"if (Test-Path $key) {{\n"
        f"  Remove-ItemProperty -Path $key -Name '{POLICY_VALUE}' -Force "
        f"-ErrorAction SilentlyContinue\n"
        f"}}\n"
    )
    return _run_elevated_powershell(body)


def preview_or_apply_disable(
    *,
    ids: list[str] | None = None,
    preset: str | None = None,
    dry_run: bool = True,
    confirm: str = "",
    elevate: bool = False,
    inject: dict[str, Any] | None = None,
    user_data_dir: Path | None = None,
) -> dict[str, Any]:
    """Preview or apply extension block policy.

    Targets are annotated with ``installed`` (Default profile scan) so the preview
    shows whether a block would affect anything; the written policy is unchanged.
    """
    if inject is not None:
        payload = dict(inject)
        payload.setdefault("timestamp_utc", _utc_now())
        payload.setdefault("command", "edge-extensions-disable")
        return attach_governance_envelope(payload, dry_run=dry_run)

    if is_demo_mode():
        dry_run = True

    resolved = resolve_targets(ids=ids, preset=preset)
    targets = resolved["targets"]
    errors = list(resolved["errors"])
    planned_json = build_extension_settings_json(targets) if targets else "{}"
    current = read_extension_settings() if platform.system() == "Windows" else None

    token_ok = (confirm or "") == DISABLE_TOKEN
    action_allowed = (
        (not dry_run) and token_ok and bool(targets) and not errors and not is_demo_mode()
    )

    payload: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "command": "edge-extensions-disable",
        "dry_run": dry_run,
        "confirmation_required": DISABLE_TOKEN,
        "confirm_provided_ok": token_ok,
        "action_allowed": action_allowed,
        "preset": preset,
        "targets": annotate_installed(targets, installed_extension_ids(user_data_dir)),
        "planned_ExtensionSettings": planned_json,
        "current_ExtensionSettings": current,
        "errors": errors,
        "limitations": list(LIMITATIONS),
    }

    if dry_run:
        payload["message"] = "Preview only — no Edge policy written."
        payload["operator_next_step"] = {
            "kind": "apply_edge_extension_disable",
            "command": (
                "python -m windows_network_toolkit edge-extensions-disable "
                f"--preset {preset or 'cloudflare-risk'} --dry-run false "
                f"--confirm {DISABLE_TOKEN}" + (" --elevate" if elevate else "")
            ),
            "confirmation_required": DISABLE_TOKEN,
            "reason": (
                "Same-message apply: include the exact token in your fix request "
                "to skip a second confirm turn after preview."
            ),
        }
        payload = attach_governance_envelope(payload, dry_run=True)
        append_audit_dict(
            {
                "event": "edge_extensions_disable",
                "dry_run": True,
                "target_count": len(targets),
            },
            log_name="edge-extensions-policy.jsonl",
        )
        return payload

    if errors or not targets:
        payload["message"] = "Live apply blocked: no valid targets or preset/ids invalid."
        payload = attach_governance_envelope(payload, dry_run=False, policy_outcome="BLOCK")
        return payload

    if not token_ok:
        payload["message"] = f"Live apply blocked: confirm must be exactly {DISABLE_TOKEN}."
        payload = attach_governance_envelope(payload, dry_run=False, policy_outcome="BLOCK")
        append_audit_dict(
            {
                "event": "edge_extensions_disable_blocked",
                "reason": "bad_confirm",
            },
            log_name="edge-extensions-policy.jsonl",
        )
        return payload

    if platform.system() != "Windows":
        payload["message"] = "edge-extensions-disable apply requires Windows."
        payload["unsupported_platform"] = True
        payload = attach_governance_envelope(payload, dry_run=False, policy_outcome="BLOCK")
        return payload

    write_result = (
        write_extension_settings_elevated(planned_json)
        if elevate
        else write_extension_settings(planned_json)
    )
    if not write_result.get("ok") and not elevate:
        # Retry path hint — do not auto-elevate without --elevate
        write_result["hint"] = "Re-run with --elevate if Policies\\Microsoft\\Edge is ACL-locked."

    payload["write_result"] = write_result
    payload["mutated"] = bool(write_result.get("ok"))
    payload["message"] = (
        "Applied ExtensionSettings block for listed IDs only."
        if write_result.get("ok")
        else "Policy write failed — see write_result; try --elevate."
    )
    payload = attach_governance_envelope(payload, dry_run=False)
    append_audit_dict(
        {
            "event": "edge_extensions_disable",
            "dry_run": False,
            "mutated": payload["mutated"],
            "target_count": len(targets),
            "elevated": bool(elevate),
        },
        log_name="edge-extensions-policy.jsonl",
    )
    return payload


def preview_or_apply_restore(
    *,
    dry_run: bool = True,
    confirm: str = "",
    elevate: bool = False,
    inject: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Preview or remove ExtensionSettings policy value."""
    if inject is not None:
        payload = dict(inject)
        payload.setdefault("timestamp_utc", _utc_now())
        payload.setdefault("command", "edge-extensions-restore")
        return attach_governance_envelope(payload, dry_run=dry_run)

    if is_demo_mode():
        dry_run = True

    current = read_extension_settings() if platform.system() == "Windows" else None
    token_ok = (confirm or "") == RESTORE_TOKEN
    action_allowed = (not dry_run) and token_ok and not is_demo_mode()

    payload: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "command": "edge-extensions-restore",
        "dry_run": dry_run,
        "confirmation_required": RESTORE_TOKEN,
        "confirm_provided_ok": token_ok,
        "action_allowed": action_allowed,
        "current_ExtensionSettings": current,
        "limitations": list(LIMITATIONS),
    }

    if dry_run:
        payload["message"] = "Preview only — ExtensionSettings not removed."
        payload["operator_next_step"] = {
            "kind": "apply_edge_extension_restore",
            "command": (
                "python -m windows_network_toolkit edge-extensions-restore "
                f"--dry-run false --confirm {RESTORE_TOKEN}" + (" --elevate" if elevate else "")
            ),
            "confirmation_required": RESTORE_TOKEN,
        }
        payload = attach_governance_envelope(payload, dry_run=True)
        append_audit_dict(
            {"event": "edge_extensions_restore", "dry_run": True},
            log_name="edge-extensions-policy.jsonl",
        )
        return payload

    if not token_ok:
        payload["message"] = f"Live apply blocked: confirm must be exactly {RESTORE_TOKEN}."
        payload = attach_governance_envelope(payload, dry_run=False, policy_outcome="BLOCK")
        return payload

    if platform.system() != "Windows":
        payload["unsupported_platform"] = True
        payload["message"] = "edge-extensions-restore apply requires Windows."
        payload = attach_governance_envelope(payload, dry_run=False, policy_outcome="BLOCK")
        return payload

    delete_result = delete_extension_settings_elevated() if elevate else delete_extension_settings()
    if not delete_result.get("ok") and not elevate:
        delete_result["hint"] = "Re-run with --elevate if Policies\\Microsoft\\Edge is ACL-locked."

    payload["delete_result"] = delete_result
    payload["mutated"] = bool(delete_result.get("ok"))
    payload["message"] = (
        "Removed ExtensionSettings policy value."
        if delete_result.get("ok")
        else "Policy delete failed — see delete_result; try --elevate."
    )
    payload = attach_governance_envelope(payload, dry_run=False)
    append_audit_dict(
        {
            "event": "edge_extensions_restore",
            "dry_run": False,
            "mutated": payload["mutated"],
            "elevated": bool(elevate),
        },
        log_name="edge-extensions-policy.jsonl",
    )
    return payload

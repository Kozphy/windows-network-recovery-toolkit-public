"""Emergency HKCU WinINET proxy fix — localhost-only server clear by default."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from src.proxy_guard.parser import parse_proxy_server
from src.proxy_guard.registry import read_proxy_registry
from src.proxy_guard.remediation import (
    _INTERNET_SETTINGS_KEY,
    CONFIRMATION_PHRASE,
    ProxyDisableMutation,
    validate_action_confirmation,
)
from src.repair.executor import apply_mutations

CONFIRM_CLEAR_PAC = "CLEAR_PAC_TOO"
_CONNECTIONS_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
_PROXY_TYPE_PROXY = 0x02


def _custody_proxy_fix(event: str, payload: dict[str, Any], *, confirmation_supplied: bool) -> None:
    try:
        from src.platform_core.audit.custody import append_custody_event

        append_custody_event(
            event,
            actor="proxy_fix",
            subsystem="proxy_fix",
            dry_run=bool(payload.get("dry_run")),
            confirmation_supplied=confirmation_supplied,
            before=payload.get("before") if isinstance(payload.get("before"), dict) else None,
            after=payload.get("after") if isinstance(payload.get("after"), dict) else None,
            outcome="applied" if payload.get("action_allowed") else "blocked_or_preview",
            limitations=list(payload.get("limitations") or []),
            extra={"reason": payload.get("reason"), "prefer_direct": payload.get("prefer_direct")},
            soft_fail=True,
        )
    except Exception:
        pass


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def clear_wininet_connection_proxy_blob() -> dict[str, Any]:
    """Clear manual-proxy bits in DefaultConnectionSettings / SavedLegacySettings.

    LinkedIn and other WinINET clients often honor the binary Connections blob even
    after ProxyEnable/ProxyServer are cleared. This is HKCU-only and localhost-safe.
    """
    import winreg

    cleared: list[str] = []
    errors: list[str] = []
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            _CONNECTIONS_SUBKEY,
            0,
            winreg.KEY_READ | winreg.KEY_SET_VALUE,
        ) as key:
            for value_name in ("DefaultConnectionSettings", "SavedLegacySettings"):
                try:
                    raw, value_type = winreg.QueryValueEx(key, value_name)
                except OSError:
                    continue
                if value_type != winreg.REG_BINARY or not isinstance(raw, (bytes, bytearray)):
                    continue
                data = bytearray(raw)
                if len(data) < 16:
                    continue
                before_flags = data[8]
                data[8] = before_flags & ~_PROXY_TYPE_PROXY
                data[12] = 0
                data[13] = 0
                data[14] = 0
                data[15] = 0
                if data != raw:
                    winreg.SetValueEx(key, value_name, 0, winreg.REG_BINARY, bytes(data))
                    cleared.append(value_name)
    except OSError as exc:
        errors.append(str(exc))
    return {
        "cleared_values": cleared,
        "errors": errors,
        "action_taken": "cleared" if cleared else ("unchanged" if not errors else "failed"),
    }


def build_proxy_fix_mutations(
    *,
    proxy_server: str | None,
    clear_pac: bool,
) -> tuple[tuple[ProxyDisableMutation, ...], tuple[str, ...]]:
    """Build mutations: always disable; clear ProxyServer only for localhost."""
    parsed = parse_proxy_server(proxy_server)
    lines = [
        f'reg add "{_INTERNET_SETTINGS_KEY}" /v ProxyEnable /t REG_DWORD /d 0 /f',
    ]
    mutations: list[ProxyDisableMutation] = [
        ProxyDisableMutation(
            argv=(
                "reg",
                "add",
                _INTERNET_SETTINGS_KEY,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ),
            human=lines[0],
        )
    ]
    if parsed.is_localhost_proxy and proxy_server:
        lines.append(f'reg delete "{_INTERNET_SETTINGS_KEY}" /v ProxyServer /f')
        mutations.append(
            ProxyDisableMutation(
                argv=("reg", "delete", _INTERNET_SETTINGS_KEY, "/v", "ProxyServer", "/f"),
                human=lines[-1],
            )
        )
    elif proxy_server:
        lines.append("ProxyServer not cleared — non-localhost corporate proxy preserved.")
    if clear_pac:
        lines.append(f'reg delete "{_INTERNET_SETTINGS_KEY}" /v AutoConfigURL /f')
        mutations.append(
            ProxyDisableMutation(
                argv=("reg", "delete", _INTERNET_SETTINGS_KEY, "/v", "AutoConfigURL", "/f"),
                human=lines[-1],
            )
        )
    lines.append("WinHTTP unchanged; observation is not proof of root cause.")
    return tuple(mutations), tuple(lines)


def apply_proxy_fix(
    *,
    dry_run: bool = True,
    confirm: str = "",
    clear_pac: bool = False,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Preview or apply HKCU WinINET proxy fix with typed confirmation."""
    subprocess_run = run if run is not None else subprocess.run
    reg = read_proxy_registry(run=subprocess_run)
    parsed = parse_proxy_server(reg.proxy_server)
    requested_fields = ["ProxyEnable"]
    if parsed.is_localhost_proxy and reg.proxy_server:
        requested_fields.append("ProxyServer")
    if clear_pac:
        requested_fields.append("AutoConfigURL")

    required_confirm = CONFIRM_CLEAR_PAC if clear_pac else CONFIRMATION_PHRASE
    if dry_run:
        payload: dict[str, Any] = {
            "timestamp_utc": _now(),
            "dry_run": True,
            "planned_changes": [],
            "before": {
                "proxy_enable": reg.proxy_enable,
                "proxy_server": reg.proxy_server,
                "auto_config_url": reg.auto_config_url,
            },
            "limitations": [
                "Remediation is preview-only unless confirmed.",
                "Does not prove malware or registry writer identity.",
            ],
        }
        _mutations, human_lines = build_proxy_fix_mutations(
            proxy_server=reg.proxy_server,
            clear_pac=clear_pac,
        )
        payload["planned_changes"] = list(human_lines)
        payload["planned_changes"].append(
            "Also clear manual-proxy flag in HKCU ...\\Internet Settings\\Connections "
            "(DefaultConnectionSettings / SavedLegacySettings)."
        )
        payload["action_allowed"] = False
        payload["reason"] = "Dry-run preview only."
        _custody_proxy_fix("proxy_fix_preview", payload, confirmation_supplied=False)
        return payload

    if confirm != required_confirm:
        mutations, human_lines = build_proxy_fix_mutations(
            proxy_server=reg.proxy_server,
            clear_pac=clear_pac,
        )
        blocked = {
            "timestamp_utc": _now(),
            "dry_run": False,
            "planned_changes": list(human_lines),
            "before": {
                "proxy_enable": reg.proxy_enable,
                "proxy_server": reg.proxy_server,
                "auto_config_url": reg.auto_config_url,
            },
            "action_allowed": False,
            "reason": f"Typed confirmation required: {required_confirm}",
            "limitations": [
                "Remediation is preview-only unless confirmed.",
                "Does not prove malware or registry writer identity.",
            ],
        }
        _custody_proxy_fix("proxy_fix_blocked", blocked, confirmation_supplied=False)
        return blocked

    decision, reason, _action = validate_action_confirmation(
        action_id="disable_wininet_proxy",
        dry_run=False,
        confirmation=CONFIRMATION_PHRASE if not clear_pac else confirm,
        requested_registry_fields=tuple(requested_fields),
    )
    mutations, human_lines = build_proxy_fix_mutations(
        proxy_server=reg.proxy_server,
        clear_pac=clear_pac,
    )
    payload = {
        "timestamp_utc": _now(),
        "dry_run": False,
        "planned_changes": list(human_lines),
        "before": {
            "proxy_enable": reg.proxy_enable,
            "proxy_server": reg.proxy_server,
            "auto_config_url": reg.auto_config_url,
        },
        "limitations": [
            "Remediation is preview-only unless confirmed.",
            "Does not prove malware or registry writer identity.",
        ],
    }
    if decision != "ALLOW":
        payload["action_allowed"] = False
        payload["reason"] = reason or f"Typed confirmation required: {required_confirm}"
        return payload
    if clear_pac and confirm != CONFIRM_CLEAR_PAC:
        payload["action_allowed"] = False
        payload["reason"] = f"Typed confirmation required: {CONFIRM_CLEAR_PAC}"
        return payload
    apply_mutations(mutations, dry_run=False)
    blob = clear_wininet_connection_proxy_blob()
    after = read_proxy_registry(run=subprocess_run)
    payload["action_allowed"] = True
    payload["connection_settings_blob"] = blob
    payload["after"] = {
        "proxy_enable": after.proxy_enable,
        "proxy_server": after.proxy_server,
        "auto_config_url": after.auto_config_url,
    }
    payload["reason"] = "HKCU WinINET proxy fix applied (including Connections blob)."
    _custody_proxy_fix("proxy_fix_applied", payload, confirmation_supplied=True)
    return payload

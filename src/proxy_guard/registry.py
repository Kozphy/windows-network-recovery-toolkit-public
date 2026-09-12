"""HKCU WinINET proxy key reads via ``reg query`` (Windows).

System position:
    Consumed by Proxy Guard CLIs, observability snapshot builder, and watcher loops.

Input assumptions:
    ``reg.exe`` available; path ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings``.

Output guarantees:
    ``ProxyRegistrySnapshot`` uses ``None`` for unreadable values rather than raising.

Failure modes:
    Timeout/OSError surfaces as non-zero codes inside ``read_proxy_registry`` callees via ``_run_reg_query``.

Engineering Notes:
    Keeps parsing logic local to tolerate locale-specific ``reg`` output lines.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from typing import Any

from ..core.models import ProxyRegistrySnapshot

_INTERNET_SETTINGS = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _run_reg_query(
    value_name: str,
    run: Callable[..., Any] = subprocess.run,
    *,
    timeout: float = 15.0,
) -> tuple[int, str]:
    cmd = ["reg", "query", _INTERNET_SETTINGS, "/v", value_name]
    try:
        proc = run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, out


def _parse_reg_dword(text: str) -> int | None:
    for line in text.splitlines():
        line = line.strip()
        if "REG_DWORD" in line:
            m = re.search(r"0x([0-9a-fA-F]+)", line)
            if m:
                return int(m.group(1), 16)
            m2 = re.search(r"REG_DWORD\s+(\d+)", line)
            if m2:
                return int(m2.group(1))
    return None


def _parse_reg_sz(text: str) -> str | None:
    for line in text.splitlines():
        line = line.strip()
        if "REG_SZ" in line or "REG_EXPAND_SZ" in line:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                return parts[2].strip()
            idx = line.find("REG_SZ")
            if idx == -1:
                idx = line.find("REG_EXPAND_SZ")
            if idx != -1:
                val = line[idx + 6 :].strip() if "REG_SZ" in line else line[idx + 14 :].strip()
                return val or None
    return None


def read_proxy_registry(
    *,
    run: Callable[..., Any] = subprocess.run,
    query_timeout: float = 15.0,
) -> ProxyRegistrySnapshot:
    """Read HKCU WinINET proxy keys via ``reg query`` (Windows).

    Args:
        run: ``subprocess.run`` injector for tests.
        query_timeout: Per-value subprocess timeout (seconds).

    Returns:
        Normalized snapshot; failed queries yield ``None`` fields without raising.
    """
    tkw = {"timeout": query_timeout}
    pe_code, pe_out = _run_reg_query("ProxyEnable", run=run, **tkw)
    ps_code, ps_out = _run_reg_query("ProxyServer", run=run, **tkw)
    pac_code, pac_out = _run_reg_query("AutoConfigURL", run=run, **tkw)
    ad_code, ad_out = _run_reg_query("AutoDetect", run=run, **tkw)
    po_code, po_out = _run_reg_query("ProxyOverride", run=run, **tkw)

    proxy_enable = _parse_reg_dword(pe_out) if pe_code == 0 else None
    proxy_server = _parse_reg_sz(ps_out) if ps_code == 0 else None
    auto_config_url = _parse_reg_sz(pac_out) if pac_code == 0 else None
    auto_detect = _parse_reg_dword(ad_out) if ad_code == 0 else None
    proxy_override = _parse_reg_sz(po_out) if po_code == 0 else None

    return ProxyRegistrySnapshot(
        proxy_enable=proxy_enable,
        proxy_server=proxy_server,
        auto_config_url=auto_config_url,
        auto_detect=auto_detect,
        proxy_override=proxy_override,
    )


def read_proxy_registry_with_presence(
    *,
    run: Callable[..., Any] = subprocess.run,
    query_timeout: float = 15.0,
) -> tuple[ProxyRegistrySnapshot, dict[str, bool]]:
    """Read HKCU WinINET proxy values and record whether each value name exists.

    ``presence[name]`` is ``True`` when ``reg query`` exited zero (value exists in the hive).
    This enables rollback that restores deliberate absences via ``reg delete``.

    Args:
        run: Subprocess injector (tests supply stubs).
        query_timeout: Per-query timeout seconds.

    Returns:
        Tuple of normalized snapshot plus presence map keyed by Win32 value names.
    """
    tkw = {"timeout": query_timeout}
    names_order = ("ProxyEnable", "ProxyServer", "AutoConfigURL", "AutoDetect", "ProxyOverride")
    texts: dict[str, tuple[int, str]] = {}
    for nm in names_order:
        code, out = _run_reg_query(nm, run=run, **tkw)
        texts[nm] = (code, out)

    pe_code, pe_out = texts["ProxyEnable"]
    ps_code, ps_out = texts["ProxyServer"]
    pac_code, pac_out = texts["AutoConfigURL"]
    ad_code, ad_out = texts["AutoDetect"]
    po_code, po_out = texts["ProxyOverride"]

    snapshot = ProxyRegistrySnapshot(
        proxy_enable=_parse_reg_dword(pe_out) if pe_code == 0 else None,
        proxy_server=_parse_reg_sz(ps_out) if ps_code == 0 else None,
        auto_config_url=_parse_reg_sz(pac_out) if pac_code == 0 else None,
        auto_detect=_parse_reg_dword(ad_out) if ad_code == 0 else None,
        proxy_override=_parse_reg_sz(po_out) if po_code == 0 else None,
    )
    presence: dict[str, bool] = {nm: (texts[nm][0] == 0) for nm in names_order}
    return snapshot, presence

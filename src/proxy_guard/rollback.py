"""Low-risk, reversible proxy rollback helpers (WinINET HKCU + WinHTTP reset).

Only these surfaces are automated by Proxy Guard; other network stack mutations stay manual.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any

from ..repair.executor import RegApplyResult, apply_mutations, apply_reg_argv_sequences
from .models import ProxySnapshot
from .remediation import build_user_proxy_disable_mutations

_INTERNET_SETTINGS_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def parse_netsh_winhttp_show(stdout: str) -> tuple[bool, str | None]:
    """Parse ``netsh winhttp show proxy`` text into *(direct_access, proxy_server_literal)*."""
    lowered = stdout.lower()
    if "direct access (no proxy server)" in lowered:
        return True, None
    for line in stdout.splitlines():
        ls = line.strip()
        ll = ls.lower()
        if "proxy server(s)" not in ll and "proxy-server" not in ll:
            continue
        sep = ":" if ":" in ls else "="
        if sep not in ls:
            continue
        _, rhs = ls.split(sep, 1)
        rhs = rhs.strip()
        if not rhs or rhs.lower() in {"not set", "(none)", "none"}:
            continue
        return False, rhs
    if "direct access" in lowered:
        return True, None
    return False, None


def build_wininet_restore_argv_list(lkg: ProxySnapshot) -> tuple[tuple[str, ...], ...]:
    """Build ordered ``reg.exe`` argv tuples to recreate WinINET HKCU fields from ``lkg``.

    Deletes optional string keys when snapshots store ``None``/empty strings.
    """
    cmds: list[tuple[str, ...]] = []

    def sz_or_delete(val: str | None, name: str) -> None:
        if val is None or str(val).strip() == "":
            cmds.append(
                ("reg", "delete", _INTERNET_SETTINGS_KEY, "/v", name, "/f"),
            )
        else:
            cmds.append(
                (
                    "reg",
                    "add",
                    _INTERNET_SETTINGS_KEY,
                    "/v",
                    name,
                    "/t",
                    "REG_SZ",
                    "/d",
                    str(val).strip(),
                    "/f",
                ),
            )

    sz_or_delete(lkg.proxy_server, "ProxyServer")
    sz_or_delete(lkg.auto_config_url, "AutoConfigURL")
    sz_or_delete(lkg.proxy_override, "ProxyOverride")

    if lkg.proxy_enable is not None:
        cmds.append(
            (
                "reg",
                "add",
                _INTERNET_SETTINGS_KEY,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                str(int(lkg.proxy_enable)),
                "/f",
            ),
        )
    return tuple(cmds)


def run_netsh_winhttp_set_proxy(
    *,
    proxy_server_literal: str,
    dry_run: bool,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Apply ``netsh winhttp set proxy`` with opaque ``proxy-server=`` literal (no shell)."""
    literal = proxy_server_literal.strip()
    argv = ["netsh", "winhttp", "set", "proxy", f"proxy-server={literal}"]
    if dry_run:
        return {
            "argv": argv,
            "returncode": 0,
            "stdout": "[dry-run] netsh winhttp set proxy not executed",
            "stderr": "",
        }
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "argv": argv,
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
        }
    return {
        "argv": argv,
        "returncode": int(proc.returncode),
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def execute_lkg_snapshot_rollback(
    lkg: ProxySnapshot | None,
    *,
    dry_run: bool,
    restore_winhttp: bool,
    run: Callable[..., Any] = subprocess.run,
    restore_git_npm_env: bool = False,
) -> dict[str, Any]:
    """Restore WinINET (and optionally WinHTTP) strictly from ``lkg`` snapshot values.

    Does **not** clear proxies blindly unlike :func:`execute_low_risk_proxy_rollback`.
    Git/npm/user env restoration is flagged off by default pending explicit gates.
    """
    if restore_git_npm_env:
        return {
            "rollback_kind": "lkg_denied_git_env_not_implemented_in_tooling",
            "wininet_reg": [],
            "winhttp_restore": None,
            "reason": "restore_git_npm_env_requires_separate_confirmation",
            "skipped": True,
        }
    if lkg is None:
        return {
            "rollback_kind": "lkg_restore",
            "skipped": True,
            "reason": "skipped_no_lkg",
            "wininet_reg": [],
            "winhttp_restore": None,
        }

    argv_list = build_wininet_restore_argv_list(lkg)
    reg_rows = apply_reg_argv_sequences(argv_list, dry_run=dry_run)
    wininet_audit = reg_results_to_audit(reg_rows)
    winhttp_row: dict[str, Any] | None = None
    if restore_winhttp:
        if lkg.winhttp_direct_access:
            winhttp_row = run_netsh_winhttp_reset_proxy(dry_run=dry_run, run=run)
        elif lkg.winhttp_proxy_server_literal:
            winhttp_row = run_netsh_winhttp_set_proxy(
                proxy_server_literal=lkg.winhttp_proxy_server_literal,
                dry_run=dry_run,
                run=run,
            )

    all_ok = all(r.returncode == 0 for r in reg_rows)
    if winhttp_row is not None and int(winhttp_row.get("returncode", -1)) != 0:
        all_ok = False

    return {
        "rollback_kind": "lkg_restore",
        "skipped": False,
        "success": all_ok,
        "wininet_reg": wininet_audit,
        "winhttp_restore": winhttp_row,
    }


def run_netsh_winhttp_reset_proxy(
    *,
    dry_run: bool,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Run ``netsh winhttp reset proxy`` (idempotent reset of WinHTTP proxy).

    Args:
        dry_run: When True, do not invoke ``netsh``; return a synthetic success row.
        run: ``subprocess.run`` injector for tests.

    Returns:
        JSON-serializable dict with ``argv``, ``returncode``, ``stdout``, ``stderr``.
    """
    argv = ("netsh", "winhttp", "reset", "proxy")
    if dry_run:
        return {
            "argv": list(argv),
            "returncode": 0,
            "stdout": "[dry-run] netsh not executed",
            "stderr": "",
        }
    try:
        proc = run(
            list(argv),
            capture_output=True,
            text=True,
            shell=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "argv": list(argv),
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
        }
    return {
        "argv": list(argv),
        "returncode": int(proc.returncode),
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def reg_results_to_audit(rows: tuple[RegApplyResult, ...]) -> list[dict[str, Any]]:
    """Flatten registry apply results for JSONL."""
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "argv": list(r.argv),
                "returncode": r.returncode,
                "stdout": r.stdout,
                "stderr": r.stderr,
            },
        )
    return out


def wininet_user_proxy_already_cleared(reg_dict: dict[str, Any]) -> bool:
    """Return True when WinINET user keys appear already disabled (idempotent no-op target).

    Unknown ``proxy_enable`` (``None``) returns False so callers still attempt remediation
    when registry reads were partial.

    Args:
        reg_dict: Keys like ``registry_proxy_snapshot.to_dict()`` output.

    Returns:
        True only when ``ProxyEnable`` is definitively ``0`` and ``ProxyServer`` is absent/empty.
    """
    if reg_dict.get("proxy_enable") != 0:
        return False
    ps = reg_dict.get("proxy_server")
    return ps is None or str(ps).strip() == ""


def execute_low_risk_proxy_rollback(
    *,
    dry_run: bool,
    clear_proxy_server_value: bool = True,
    reset_winhttp: bool = True,
    run: Callable[..., Any] = subprocess.run,
    current_wininet_reg: dict[str, Any] | None = None,
    skip_wininet_if_already_cleared: bool = True,
) -> dict[str, Any]:
    """Disable HKCU WinINET user proxy and optionally reset WinHTTP proxy.

    Order:
        1. ``reg add`` / ``reg delete`` mutations from :mod:`remediation` (may be skipped).
        2. ``netsh winhttp reset proxy`` when ``reset_winhttp`` is True.

    Idempotency:
        Re-running after a successful rollback yields **no WinINET argv** when
        ``current_wininet_reg`` reflects an already-cleared state (still runs WinHTTP reset
        when enabled — ``netsh winhttp reset proxy`` is safe to repeat).

    Args:
        dry_run: Skip real subprocess I/O (preview only).
        clear_proxy_server_value: Pass through to ``build_user_proxy_disable_mutations``.
        reset_winhttp: When False, skip WinHTTP reset (testing / strict WinINET-only rollback).
        run: ``subprocess.run`` injector.
        current_wininet_reg: Optional HKCU mapping before rollback (for skip optimization).
        skip_wininet_if_already_cleared: When True and state already cleared, omit ``reg.exe``.

    Returns:
        Structured audit blob suitable for ``rollback_detail`` in control-plane JSONL.
    """
    wininet_audit: list[dict[str, Any]]
    skipped = False
    if (
        skip_wininet_if_already_cleared
        and current_wininet_reg is not None
        and wininet_user_proxy_already_cleared(current_wininet_reg)
    ):
        wininet_audit = []
        skipped = True
    else:
        mutations, _ = build_user_proxy_disable_mutations(clear_proxy_server_value=clear_proxy_server_value)
        reg_results = apply_mutations(mutations, dry_run=dry_run)
        wininet_audit = reg_results_to_audit(reg_results)

    winhttp: dict[str, Any] | None = None
    if reset_winhttp:
        winhttp = run_netsh_winhttp_reset_proxy(dry_run=dry_run, run=run)
    out: dict[str, Any] = {
        "wininet_reg": wininet_audit,
        "winhttp_reset": winhttp,
        "wininet_skipped_already_cleared": skipped,
    }
    return out


_HKCU_ENVIRONMENT_KEY = r"HKCU\Environment"


def _run_external_argv_audit(
    argv: list[str],
    *,
    dry_run: bool,
    run: Callable[..., Any],
    timeout: float,
) -> dict[str, Any]:
    if dry_run:
        return {"argv": argv, "returncode": 0, "stdout": "[dry-run] not executed", "stderr": ""}
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"argv": argv, "returncode": -1, "stdout": "", "stderr": str(exc)}
    return {
        "argv": argv,
        "returncode": int(proc.returncode),
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def _git_restore_row(full_key: str, value: str | None, *, dry_run: bool, run: Callable[..., Any]) -> dict[str, Any]:
    if value is None or str(value).strip() == "":
        argv = ["git", "config", "--global", "--unset-all", full_key]
    else:
        argv = ["git", "config", "--global", full_key, str(value).strip()]
    return _run_external_argv_audit(argv, dry_run=dry_run, run=run, timeout=45.0)


def _git_row_ok(row: dict[str, Any]) -> bool:
    c = int(row.get("returncode", -1))
    argv_l = [str(x).lower() for x in (row.get("argv") or [])]
    if "unset-all" in argv_l and c in (0, 5):
        return True
    return c == 0


def _npm_restore_row(key: str, value: str | None, *, dry_run: bool, run: Callable[..., Any]) -> dict[str, Any]:
    stripped = "" if value is None else str(value).strip()
    if stripped == "" or stripped.lower() in ("null", "undefined"):
        argv = ["npm", "config", "delete", key, "--global"]
    else:
        argv = ["npm", "config", "set", key, stripped, "--global"]
    return _run_external_argv_audit(argv, dry_run=dry_run, run=run, timeout=120.0)


def _hkcu_env_restore_row(name: str, value: str | None, *, dry_run: bool, run: Callable[..., Any]) -> dict[str, Any]:
    if value is None or str(value).strip() == "":
        argv = ["reg", "delete", _HKCU_ENVIRONMENT_KEY, "/v", name, "/f"]
    else:
        argv = ["reg", "add", _HKCU_ENVIRONMENT_KEY, "/v", name, "/t", "REG_SZ", "/d", str(value).strip(), "/f"]
    return _run_external_argv_audit(argv, dry_run=dry_run, run=run, timeout=30.0)


def _env_reg_row_ok(row: dict[str, Any]) -> bool:
    c = int(row.get("returncode", -1))
    argv = row.get("argv") or []
    if "delete" in argv:
        return c in (0, 1)
    return c == 0


def execute_known_good_proxy_restore(
    target: ProxySnapshot | None,
    *,
    dry_run: bool,
    restore_winhttp: bool,
    run: Callable[..., Any] = subprocess.run,
) -> dict[str, Any]:
    """Restore WinINET, WinHTTP, Git global npm, and HKCU user env proxy vars from ``target``.

    Uses argv-only subprocesses (no ``shell=True``). Does not alter firewall rules or adapters.
    """

    if target is None:
        return {
            "rollback_kind": "known_good_restore",
            "skipped": True,
            "reason": "skipped_no_target_snapshot",
            "wininet_reg": [],
            "winhttp_restore": None,
            "git_audits": [],
            "npm_audits": [],
            "user_env_audits": [],
            "success": False,
        }

    argv_list = build_wininet_restore_argv_list(target)
    reg_rows = apply_reg_argv_sequences(argv_list, dry_run=dry_run)
    wininet_audit = reg_results_to_audit(reg_rows)
    winhttp_row: dict[str, Any] | None = None
    if restore_winhttp:
        if target.winhttp_direct_access:
            winhttp_row = run_netsh_winhttp_reset_proxy(dry_run=dry_run, run=run)
        elif target.winhttp_proxy_server_literal:
            winhttp_row = run_netsh_winhttp_set_proxy(
                proxy_server_literal=target.winhttp_proxy_server_literal,
                dry_run=dry_run,
                run=run,
            )

    git_audits = [
        _git_restore_row("http.proxy", target.git_http_proxy, dry_run=dry_run, run=run),
        _git_restore_row("https.proxy", target.git_https_proxy, dry_run=dry_run, run=run),
    ]
    npm_audits = [
        _npm_restore_row("proxy", target.npm_proxy, dry_run=dry_run, run=run),
        _npm_restore_row("https-proxy", target.npm_https_proxy, dry_run=dry_run, run=run),
    ]
    user_env_audits = [
        _hkcu_env_restore_row("HTTP_PROXY", target.user_http_proxy, dry_run=dry_run, run=run),
        _hkcu_env_restore_row("HTTPS_PROXY", target.user_https_proxy, dry_run=dry_run, run=run),
        _hkcu_env_restore_row("ALL_PROXY", target.user_all_proxy, dry_run=dry_run, run=run),
        _hkcu_env_restore_row("NO_PROXY", target.user_no_proxy, dry_run=dry_run, run=run),
    ]

    inet_ok = all(r.returncode == 0 for r in reg_rows)
    wh_ok = True
    if winhttp_row is not None and int(winhttp_row.get("returncode", -1)) != 0:
        wh_ok = False

    git_ok = all(_git_row_ok(row) for row in git_audits)
    npm_ok = all(int(row.get("returncode", -1)) == 0 for row in npm_audits)
    env_ok = all(_env_reg_row_ok(row) for row in user_env_audits)

    overall = inet_ok and wh_ok and git_ok and npm_ok and env_ok

    return {
        "rollback_kind": "known_good_restore",
        "skipped": False,
        "success": overall,
        "wininet_reg": wininet_audit,
        "winhttp_restore": winhttp_row,
        "git_audits": git_audits,
        "npm_audits": npm_audits,
        "user_env_audits": user_env_audits,
    }

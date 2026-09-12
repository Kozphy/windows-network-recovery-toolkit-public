"""Compose :class:`~src.proxy_guard.models.ProxySnapshot` from HKCU probes and lightweight CLI reads."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ..core.time_utils import utc_now_iso

if TYPE_CHECKING:
    pass

from ..core.models import ProxyRegistrySnapshot
from .models import ProxySnapshot
from .registry import read_proxy_registry
from .rollback import parse_netsh_winhttp_show


def _capture_winhttp_stdout(*, run: Callable[..., Any]) -> str:
    try:
        proc = run(
            ["netsh", "winhttp", "show", "proxy"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout or ""


def _user_env_optional(name: str) -> str | None:
    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:  # type: ignore[name-defined]
            val, _ = winreg.QueryValueEx(key, name)  # type: ignore[attr-defined]
    except OSError:
        return None
    if isinstance(val, str) and val.strip():
        return val
    return None


def _run_text(cmd: list[str], *, run: Callable[..., Any], timeout: float) -> str | None:
    try:
        proc = run(cmd, capture_output=True, text=True, shell=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    return out or None


def capture_proxy_snapshot(
    *,
    run: Callable[..., Any] = subprocess.run,
    registry_snapshot: ProxyRegistrySnapshot | None = None,
    query_timeout: float = 15.0,
    skip_optional_cli: bool = False,
) -> ProxySnapshot:
    """Materialize one :class:`ProxySnapshot` rooted in ``registry_snapshot`` (or freshly probed HKCU).

    Side effects:
        Invokes subprocesses for HKCU probes (unless callers pass registry snapshot retrieved
        elsewhere), ``netsh winhttp``, and optional ``git config`` / ``npm config``.
    """
    reg = registry_snapshot or read_proxy_registry(run=run, query_timeout=query_timeout)
    winhttp_txt = _capture_winhttp_stdout(run=run)
    direct, srv = parse_netsh_winhttp_show(winhttp_txt)

    git_http = git_https = npm_p = npm_h = None
    if not skip_optional_cli:
        git_http = _run_text(["git", "config", "--global", "--get", "http.proxy"], run=run, timeout=8.0)
        git_https = _run_text(["git", "config", "--global", "--get", "https.proxy"], run=run, timeout=8.0)
        npm_p_raw = _run_text(["npm", "config", "get", "proxy"], run=run, timeout=12.0)
        npm_h_raw = _run_text(["npm", "config", "get", "https-proxy"], run=run, timeout=12.0)
        npm_p = None if npm_p_raw in (None, "null", "undefined") else npm_p_raw
        npm_h = None if npm_h_raw in (None, "null", "undefined") else npm_h_raw

    user_http = _user_env_optional("HTTP_PROXY") or _user_env_optional("http_proxy")
    user_https = _user_env_optional("HTTPS_PROXY") or _user_env_optional("https_proxy")
    user_all = _user_env_optional("ALL_PROXY") or _user_env_optional("all_proxy")
    user_no = _user_env_optional("NO_PROXY") or _user_env_optional("no_proxy")

    return ProxySnapshot(
        proxy_enable=reg.proxy_enable,
        proxy_server=reg.proxy_server,
        proxy_override=reg.proxy_override,
        auto_config_url=reg.auto_config_url,
        auto_detect=reg.auto_detect,
        winhttp_proxy=winhttp_txt,
        winhttp_direct_access=direct,
        winhttp_proxy_server_literal=srv,
        git_http_proxy=git_http,
        git_https_proxy=git_https,
        npm_proxy=npm_p,
        npm_https_proxy=npm_h,
        user_http_proxy=user_http,
        user_https_proxy=user_https,
        user_all_proxy=user_all,
        user_no_proxy=user_no,
        captured_at=utc_now_iso(),
    )


def save_lkg_snapshot(path: Any, snapshot: ProxySnapshot) -> None:
    """Persist ``snapshot`` UTF-JSON for rollback restore."""
    import json
    from pathlib import Path

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(snapshot.to_jsonable(), indent=2), encoding="utf-8")


def load_lkg_snapshot(path: Any) -> ProxySnapshot | None:
    """Load persisted LKG; returns ``None`` when absent or malformed."""
    import json
    from pathlib import Path

    p = Path(path)
    if not p.is_file():
        return None
    try:
        blob = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(blob, dict):
        return None
    try:
        return ProxySnapshot.from_json_dict(blob)
    except (KeyError, TypeError, ValueError):
        return None

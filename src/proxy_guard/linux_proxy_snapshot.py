"""Read-only Linux proxy configuration snapshot (env, /etc/environment, gsettings, NM, apt).

Observe-only scaffold — no remediation. Distinct from Windows :mod:`src.proxy_guard.snapshot_capture`.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..core.time_utils import utc_now_iso

_ENV_KEYS = (
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "no_proxy",
    "NO_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "ftp_proxy",
    "FTP_PROXY",
)

_GSETTINGS_SCHEMAS = (
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
    ("org.gnome.system.proxy.socks", "host"),
    ("org.gnome.system.proxy.socks", "port"),
    ("org.gnome.system.proxy", "autoconfig-url"),
)


@dataclass(frozen=True)
class LinuxProxySnapshot:
    """Normalized read-only proxy state for Linux / WSL hosts."""

    captured_at_utc: str
    os_family: str
    linux_distro: str
    wsl: bool
    environment: dict[str, str]
    etc_environment: dict[str, str]
    gsettings: dict[str, str | None]
    networkmanager: dict[str, str | None]
    apt_proxy_lines: list[str]
    sources: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def proxy_configured(self) -> bool:
        """Proxy configured.

        Args:
            None.

        Returns:
            The bool result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        if self.environment or self.etc_environment:
            return True
        mode = (self.gsettings.get("org.gnome.system.proxy/mode") or "").strip()
        if mode and mode not in ("none", "manual", ""):
            return True
        if mode == "manual":
            for key in self.gsettings:
                if key.endswith("/host") and self.gsettings.get(key):
                    return True
        if any(self.networkmanager.get(k) for k in ("proxy-method", "proxy")):
            return True
        return bool(self.apt_proxy_lines)

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        row = asdict(self)
        row["proxy_configured"] = self.proxy_configured()
        return row


def _read_process_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    source = env if env is not None else os.environ
    out: dict[str, str] = {}
    for key in _ENV_KEYS:
        val = source.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()
    return out


def _parse_environment_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key.lower() in {k.lower() for k in _ENV_KEYS} and val:
            out[key] = val
    return out


def _run_text(
    cmd: list[str],
    *,
    run: Callable[..., Any],
    timeout: float = 8.0,
) -> str | None:
    try:
        proc = run(cmd, capture_output=True, text=True, shell=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    return out or None


def _read_gsettings(*, run: Callable[..., Any]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for schema, key in _GSETTINGS_SCHEMAS:
        label = f"{schema}/{key}"
        val = _run_text(["gsettings", "get", schema, key], run=run, timeout=6.0)
        out[label] = val
    return out


def _read_networkmanager_proxy(*, run: Callable[..., Any]) -> dict[str, str | None]:
    active = _run_text(
        ["nmcli", "-t", "-f", "NAME,UUID", "connection", "show", "--active"],
        run=run,
        timeout=8.0,
    )
    if not active:
        return {"active_connection": None, "proxy-method": None, "proxy": None}
    first = active.splitlines()[0]
    name = first.split(":", 1)[0] if ":" in first else first
    detail = _run_text(
        ["nmcli", "connection", "show", name],
        run=run,
        timeout=10.0,
    )
    proxy_method = proxy_blob = None
    if detail:
        for line in detail.splitlines():
            low = line.lower()
            if low.startswith("proxy.method:"):
                proxy_method = line.split(":", 1)[-1].strip()
            elif low.startswith("proxy:") and not low.startswith("proxy.method"):
                proxy_blob = line.split(":", 1)[-1].strip()
    return {
        "active_connection": name,
        "proxy-method": proxy_method,
        "proxy": proxy_blob,
    }


def _scan_apt_proxy_conf(apt_dir: Path | None = None) -> list[str]:
    root = apt_dir or Path("/etc/apt/apt.conf.d")
    lines: list[str] = []
    if not root.is_dir():
        return lines
    proxy_re = re.compile(r"Acquire::.*Proxy", re.IGNORECASE)
    try:
        paths = sorted(root.iterdir())
    except OSError:
        return lines
    for path in paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            if proxy_re.search(line):
                lines.append(f"{path.name}: {line.strip()}")
    return lines


def collect_linux_proxy_snapshot(
    *,
    run: Callable[..., Any] = subprocess.run,
    env: Mapping[str, str] | None = None,
    etc_environment_path: Path | None = None,
    apt_conf_dir: Path | None = None,
    skip_optional_cli: bool = False,
) -> LinuxProxySnapshot:
    """Collect read-only Linux proxy configuration from multiple sources."""
    from platform_core.network_diagnostics.base import detect_linux_distro, is_wsl

    sources: list[str] = []
    limitations: list[str] = []

    environment = _read_process_env(env)
    if environment:
        sources.append("process_environment")

    etc_path = etc_environment_path or Path("/etc/environment")
    etc_environment = _parse_environment_file(etc_path)
    if etc_environment:
        sources.append("etc_environment")
    elif etc_path.exists():
        sources.append("etc_environment")

    gsettings: dict[str, str | None] = {}
    networkmanager: dict[str, str | None] = {
        "active_connection": None,
        "proxy-method": None,
        "proxy": None,
    }
    apt_proxy_lines: list[str] = []

    if not skip_optional_cli:
        gsettings = _read_gsettings(run=run)
        if any(v for v in gsettings.values()):
            sources.append("gsettings")
        elif _run_text(["which", "gsettings"], run=run, timeout=3.0) is None:
            limitations.append("gsettings_unavailable")

        networkmanager = _read_networkmanager_proxy(run=run)
        if networkmanager.get("proxy-method") or networkmanager.get("proxy"):
            sources.append("networkmanager")
        elif _run_text(["which", "nmcli"], run=run, timeout=3.0) is None:
            limitations.append("nmcli_unavailable")

    apt_proxy_lines = _scan_apt_proxy_conf(apt_conf_dir)
    if apt_proxy_lines:
        sources.append("apt_conf")

    return LinuxProxySnapshot(
        captured_at_utc=utc_now_iso(),
        os_family="linux",
        linux_distro=detect_linux_distro(),
        wsl=is_wsl(),
        environment=environment,
        etc_environment=etc_environment,
        gsettings=gsettings,
        networkmanager=networkmanager,
        apt_proxy_lines=apt_proxy_lines,
        sources=sources,
        limitations=limitations,
    )

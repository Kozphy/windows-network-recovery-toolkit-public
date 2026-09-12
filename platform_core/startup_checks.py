"""Startup validation: dependencies, filesystem, and configuration."""

from __future__ import annotations

import importlib
import shutil
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from platform_core.models import utc_now_iso
from platform_core.settings import PlatformSettings, get_settings

CheckStatus = Literal["ok", "warning", "failed"]


@dataclass
class StartupCheck:
    """Represent StartupCheck data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    name: str
    status: CheckStatus
    detail: str = ""


@dataclass
class StartupReport:
    """Represent StartupReport data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    ok: bool
    checks: list[StartupCheck] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, object]:
        """Return a serialized to dict representation.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return {
            "ok": self.ok,
            "started_at": self.started_at,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail} for c in self.checks
            ],
        }


class StartupState:
    """Process-wide startup report populated during FastAPI lifespan."""

    report: StartupReport | None = None


startup_state = StartupState()


def _check_python_version() -> StartupCheck:
    return StartupCheck("python_version", "ok", detail=".".join(map(str, sys.version_info[:3])))
    return StartupCheck(
        "python_version",
        "failed",
        detail=f"Python 3.11+ required; found {sys.version_info.major}.{sys.version_info.minor}",
    )


def _check_imports() -> StartupCheck:
    modules = ("fastapi", "pydantic", "platform_core.storage", "platform_core.policy")
    missing: list[str] = []
    for name in modules:
        try:
            importlib.import_module(name)
        except ImportError:
            missing.append(name)
    if missing:
        return StartupCheck(
            "dependencies", "failed", detail=f"missing modules: {', '.join(missing)}"
        )
    return StartupCheck("dependencies", "ok", detail="core imports available")


def _check_ping_binary(settings: PlatformSettings) -> StartupCheck:
    if shutil.which("ping") is None:
        if settings.require_ping_binary:
            return StartupCheck("ping_binary", "failed", detail="ping not found on PATH")
        return StartupCheck(
            "ping_binary", "warning", detail="ping not found; reachability probes degraded"
        )
    return StartupCheck("ping_binary", "ok", detail="ping available")


def _check_data_dir(settings: PlatformSettings) -> StartupCheck:
    path = settings.platform_data_dir
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_probe"
        probe.write_text(datetime.now(UTC).isoformat(), encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        return StartupCheck("filesystem", "failed", detail=f"cannot write {path}: {exc}")
    return StartupCheck("filesystem", "ok", detail=str(path.resolve()))


def _check_configuration(settings: PlatformSettings) -> StartupCheck:
    warnings: list[str] = []
    if not settings.platform_safe_mode:
        warnings.append("PLATFORM_SAFE_MODE=0 disables safe defaults")
    key = settings.resolved_api_key()
    if key and key in {"dev-platform-key-change-me", "change-me", "test"}:
        warnings.append("PLATFORM_API_KEY uses a documented demo default")
    if warnings:
        return StartupCheck("configuration", "warning", detail="; ".join(warnings))
    return StartupCheck("configuration", "ok", detail="configuration validated")


def run_startup_checks(settings: PlatformSettings | None = None) -> StartupReport:
    """Run dependency, filesystem, and configuration checks."""
    cfg = settings or get_settings()
    checks = [
        _check_python_version(),
        _check_imports(),
        _check_ping_binary(cfg),
        _check_data_dir(cfg),
        _check_configuration(cfg),
    ]
    fatal = any(c.status == "failed" for c in checks)
    ok = not fatal
    return StartupReport(ok=ok, checks=checks)

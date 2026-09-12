"""Runtime configuration for Proxy Guard (environment variables, optional JSON file, CLI overrides).

Module responsibility:
    Merge probe timeouts, rollback rate limits, and policy artifacts into immutable :class:`ProxyGuardServiceConfig`
    consumed by ``proxy-guard`` / ``proxy-watch`` services—single source for subprocess probe tuning.

System placement:
    Imported by proxy guard CLI handlers and service runners after :func:`~src.proxy_guard.policy.load_proxy_guard_policy`.

Key invariants:
    * Numeric precedence: defaults → optional JSON ``config_file`` blob → environment variable overrides (see :func:`build_service_config`).
    * JSON root must be an object or :func:`load_optional_json_config` raises :exc:`ValueError`.

Input assumptions:
    Environment variables parse leniently—invalid floats/ints fall back to baked defaults without crashing callers.

Output guarantees:
    :class:`ProxyGuardServiceConfig` is frozen after construction; mutation happens via :func:`merge_config_overrides` in tests only.

Side effects:
    Reads optional JSON path from disk when ``config_file`` resolves to an existing file.

Failure modes:
    Missing env vars silently retain defaults; malformed JSON raises before service loop starts when explicitly loaded.

Audit Notes:
    Rollback limits guard against rapid ``reg`` replay storms—tune via env for incident response but record rationale when widening limits.

Engineering Notes:
    ``legacy_control_kwargs_to_config`` preserves older control-plane signatures while routing everything through :func:`build_service_config`.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .policy import ProxyGuardPolicy


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def load_optional_json_config(path: Path | None) -> dict[str, Any]:
    """Load a JSON object from disk; missing path yields empty dict.

    Args:
        path: Optional repository-relative config file.

    Returns:
        Parsed mapping.

    Raises:
        ValueError: When JSON root is not an object.

    Side effects:
        Reads file bytes once.
    """
    if path is None or not path.is_file():
        return {}
    blob = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(blob, dict):
        raise ValueError(f"config root must be an object: {path}")
    return blob


@dataclass(frozen=True)
class ProbeRetrySettings:
    """Subprocess probe retry policy (registry reads)."""

    timeout_seconds: float = 15.0
    max_attempts: int = 3
    backoff_seconds: float = 0.75


@dataclass(frozen=True)
class RollbackLimitSettings:
    """Guards against rollback storms (infinite loops, flapping malware)."""

    cooldown_seconds: float = 60.0
    window_seconds: float = 300.0
    max_rollbacks_per_window: int = 5


@dataclass(frozen=True)
class ProxyGuardServiceConfig:
    """Full service configuration (no argparse types).

    Business logic consumes only this object; CLI builds it via :func:`build_service_config`.
    """

    policy: ProxyGuardPolicy
    jsonl_path: Path
    interval_seconds: float
    once: bool
    auto_rollback: bool
    dry_run_rollback: bool
    run: Callable[..., Any]
    probe: ProbeRetrySettings
    rollback_limits: RollbackLimitSettings
    structured_log_path: Path | None
    exit_after_registry_change_events: int | None = None
    repo_root: Path | None = None
    attribution_mode: str = "auto"
    trust_current_lkg: bool = False
    restore_git_npm_env: bool = False
    cli_rollback: bool = False
    rollback_confirm_phrase: str = ""
    known_good_snapshot: Any | None = None
    evidence_csv: str | None = None
    attribution_since_seconds: int = 90
    stdout_json: bool = False


def build_service_config(
    *,
    policy: ProxyGuardPolicy,
    jsonl_path: Path,
    interval: float,
    once: bool,
    auto_rollback: bool,
    dry_run_rollback: bool,
    run: Callable[..., Any],
    config_file: Path | None = None,
    structured_log_path: Path | None = None,
    exit_after_registry_change_events: int | None = None,
    repo_root: Path | None = None,
    attribution_mode: str = "auto",
    trust_current_lkg: bool = False,
    restore_git_npm_env: bool = False,
    cli_rollback: bool = False,
    rollback_confirm_phrase: str = "",
    known_good_snapshot: Any | None = None,
    evidence_csv: str | None = None,
    attribution_since_seconds: int = 90,
    stdout_json: bool = False,
) -> ProxyGuardServiceConfig:
    """Merge CLI args with optional JSON file and environment variables.

    Precedence for numeric tuning: defaults → JSON file → environment overrides.

    Env vars:
        ``PROXY_GUARD_PROBE_TIMEOUT`` — per ``reg query`` timeout (seconds).
        ``PROXY_GUARD_PROBE_MAX_ATTEMPTS`` — full snapshot retries.
        ``PROXY_GUARD_PROBE_BACKOFF`` — backoff base between attempts (seconds).
        ``PROXY_GUARD_ROLLBACK_COOLDOWN`` — minimum seconds between auto-rollbacks.
        ``PROXY_GUARD_ROLLBACK_WINDOW`` — rolling window for rate limit (seconds).
        ``PROXY_GUARD_ROLLBACK_MAX_PER_WINDOW`` — max auto-rollbacks in window.

    JSON keys (optional file):
        ``probe``: ``{"timeout_seconds", "max_attempts", "backoff_seconds"}``
        ``rollback_limits``: ``{"cooldown_seconds", "window_seconds", "max_rollbacks_per_window"}``
    """
    file_blob = load_optional_json_config(config_file)
    probe_blob = file_blob.get("probe") if isinstance(file_blob.get("probe"), dict) else {}
    rb_blob = file_blob.get("rollback_limits") if isinstance(file_blob.get("rollback_limits"), dict) else {}

    base_timeout = float(probe_blob.get("timeout_seconds", 15.0))
    base_attempts = int(probe_blob.get("max_attempts", 3))
    base_backoff = float(probe_blob.get("backoff_seconds", 0.75))
    probe = ProbeRetrySettings(
        timeout_seconds=_env_float("PROXY_GUARD_PROBE_TIMEOUT", base_timeout),
        max_attempts=_env_int("PROXY_GUARD_PROBE_MAX_ATTEMPTS", base_attempts),
        backoff_seconds=_env_float("PROXY_GUARD_PROBE_BACKOFF", base_backoff),
    )

    base_cool = float(rb_blob.get("cooldown_seconds", 60.0))
    base_win = float(rb_blob.get("window_seconds", 300.0))
    base_max_rb = int(rb_blob.get("max_rollbacks_per_window", 5))
    rollback_limits = RollbackLimitSettings(
        cooldown_seconds=_env_float("PROXY_GUARD_ROLLBACK_COOLDOWN", base_cool),
        window_seconds=_env_float("PROXY_GUARD_ROLLBACK_WINDOW", base_win),
        max_rollbacks_per_window=_env_int("PROXY_GUARD_ROLLBACK_MAX_PER_WINDOW", base_max_rb),
    )

    return ProxyGuardServiceConfig(
        policy=policy,
        jsonl_path=jsonl_path,
        interval_seconds=max(1.0, float(interval)),
        once=once,
        auto_rollback=auto_rollback,
        dry_run_rollback=dry_run_rollback,
        run=run,
        probe=probe,
        rollback_limits=rollback_limits,
        structured_log_path=structured_log_path,
        exit_after_registry_change_events=exit_after_registry_change_events,
        repo_root=repo_root,
        attribution_mode=attribution_mode,
        trust_current_lkg=trust_current_lkg,
        restore_git_npm_env=restore_git_npm_env,
        cli_rollback=cli_rollback,
        rollback_confirm_phrase=rollback_confirm_phrase,
        known_good_snapshot=known_good_snapshot,
        evidence_csv=evidence_csv,
        attribution_since_seconds=max(60, int(attribution_since_seconds)),
        stdout_json=stdout_json,
    )


def legacy_control_kwargs_to_config(
    *,
    interval: float,
    once: bool,
    auto_rollback: bool,
    policy: ProxyGuardPolicy,
    jsonl_path: Path,
    dry_run_rollback: bool,
    run: Callable[..., Any],
    exit_after_registry_change_events: int | None = None,
    repo_root: Path | None = None,
    attribution_mode: str = "auto",
    trust_current_lkg: bool = False,
    restore_git_npm_env: bool = False,
    cli_rollback: bool = False,
    rollback_confirm_phrase: str = "",
    known_good_snapshot: Any | None = None,
    evidence_csv: str | None = None,
    attribution_since_seconds: int = 90,
) -> ProxyGuardServiceConfig:
    """Map legacy :func:`run_proxy_guard_control` kwargs to :class:`ProxyGuardServiceConfig`."""
    return build_service_config(
        policy=policy,
        jsonl_path=jsonl_path,
        interval=interval,
        once=once,
        auto_rollback=auto_rollback,
        dry_run_rollback=dry_run_rollback,
        run=run,
        config_file=None,
        structured_log_path=None,
        exit_after_registry_change_events=exit_after_registry_change_events,
        repo_root=repo_root,
        attribution_mode=attribution_mode,
        trust_current_lkg=trust_current_lkg,
        restore_git_npm_env=restore_git_npm_env,
        cli_rollback=cli_rollback,
        rollback_confirm_phrase=rollback_confirm_phrase,
        known_good_snapshot=known_good_snapshot,
        evidence_csv=evidence_csv,
        attribution_since_seconds=attribution_since_seconds,
    )


def merge_config_overrides(base: ProxyGuardServiceConfig, **overrides: Any) -> ProxyGuardServiceConfig:
    """Return a copy with dataclass fields replaced (tests)."""
    return replace(base, **overrides)

"""Proxy Guard service entrypoints and legacy keyword adapter.

Module responsibility:
    Build :class:`~config.ProxyGuardServiceConfig` from historical kwargs and start
    the guard loop in :mod:`guard`.

System placement:
    Called by CLI ``proxy-guard`` handlers and :mod:`control` shim; bridges pytest
    fixtures that still pass flat keyword arguments.

Key invariants:
    * ``run_proxy_guard_service`` is the canonical loop starter.
    * ``legacy_control_kwargs_to_config`` preserves defaults documented in
      ``docs/proxy_guard.md``.

Side effects:
    Delegates to :mod:`guard` — registry polling, audit append, optional rollback.

Audit Notes:
    Policy object and ``jsonl_path`` passed here determine which audit sink receives
    drift rows; verify ``reports/proxy_guard_watch.jsonl`` when using watch tooling.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import ProxyGuardServiceConfig, legacy_control_kwargs_to_config
from .guard import run_proxy_guard_guard_loop
from .policy import ProxyGuardPolicy


def run_proxy_guard_service(cfg: ProxyGuardServiceConfig) -> None:
    """Run the guard loop (:mod:`guard` holds the implementation details)."""

    run_proxy_guard_guard_loop(cfg)


def run_proxy_guard_from_legacy(
    *,
    interval: float,
    once: bool,
    auto_rollback: bool,
    policy: ProxyGuardPolicy,
    jsonl_path: Path,
    dry_run_rollback: bool,
    run: Any,
    exit_after_registry_change_events: int | None = None,
    repo_root: Path | None = None,
    attribution_mode: str = "auto",
    trust_current_lkg: bool = False,
    restore_git_npm_env: bool = False,
    cli_rollback: bool = False,
    rollback_confirm_phrase: str = "",
    evidence_csv: str | None = None,
    attribution_since_seconds: int = 90,
) -> None:
    """Adapter preserving historical keyword parameters for pytest + shim callers."""

    cfg = legacy_control_kwargs_to_config(
        interval=interval,
        once=once,
        auto_rollback=auto_rollback,
        policy=policy,
        jsonl_path=jsonl_path,
        dry_run_rollback=dry_run_rollback,
        run=run,
        exit_after_registry_change_events=exit_after_registry_change_events,
        repo_root=repo_root,
        attribution_mode=attribution_mode,
        trust_current_lkg=trust_current_lkg,
        restore_git_npm_env=restore_git_npm_env,
        cli_rollback=cli_rollback,
        rollback_confirm_phrase=rollback_confirm_phrase,
        evidence_csv=evidence_csv,
        attribution_since_seconds=attribution_since_seconds,
    )
    run_proxy_guard_service(cfg)

"""Append-only audit sinks for Proxy Guard and unified ``proxy-watch`` change detection.

Module responsibility:
    Centralizes JSONL append paths for legacy multi-sink records
    (:class:`~src.proxy_guard.models.ProxyGuardAuditRecord`) and the newer
    ``proxy_change_detected`` schema consumed by ``proxy-watch`` / ``proxy-report``.

System placement:
    Imported by :mod:`~src.proxy_guard.guard`, pipeline helpers, and ``emit_proxy_change_detected_audit``
    writers. Uses :func:`~src.core.jsonl.append_jsonl` for deterministic line appends.

Key invariants:
    * All writers create parent directories before appending; callers must not rotate files from
      underneath active processes without external coordination.

Audit Notes:
    * ``logs/proxy_guard.jsonl`` rows use string ``schema_version`` ``"1"`` and must be parsed as
      newline-delimited JSON (one object per line). Malformed historical lines are skipped by
      ``proxy-report``, not repaired in place.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..core.jsonl import append_jsonl
from ..core.time_utils import utc_now_iso
from .models import ProxyGuardAuditRecord, RollbackPlan


def pipeline_audit_path(repo_root: Path) -> Path:
    """Secondary sink for unified v1 pipeline JSON (does not replace schema v2 rows)."""

    return repo_root / "logs" / "proxy_guard_pipeline_audit.jsonl"


def emit_pipeline_audit_v1(repo_root: Path, payload: dict[str, Any]) -> None:
    """Append ``schema_version`` 1 unified detect→attribute→decide→rollback audit lines."""

    path = pipeline_audit_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    append_jsonl(path, payload)


def default_audit_paths(repo_root: Path) -> dict[str, Path]:
    """Return canonical watch/actions/audit sink paths under *repo_root*."""
    return {
        "watch": repo_root / "reports" / "proxy_guard_watch.jsonl",
        "actions": repo_root / "reports" / "proxy_guard_actions.jsonl",
        "audit": repo_root / "logs" / "proxy_guard_audit.jsonl",
    }


def emit_proxy_guard_audit(record: ProxyGuardAuditRecord, *, repo_root: Path) -> None:
    """Write the same JSON object to watch/actions/audit sinks (idempotent append)."""
    paths = default_audit_paths(repo_root)
    for key in ("watch", "actions", "audit"):
        path = paths[key]
        path.parent.mkdir(parents=True, exist_ok=True)
        append_jsonl(path, record.to_jsonable())


def build_rollback_plan(
    *,
    decision: str,
    rollback_allowed: bool,
    lkg_present: bool,
    auto_rollback_enabled: bool,
    live_rollback_enabled: bool,
    explicit_winhttp_data: bool,
    restore_git_npm_env: bool,
) -> RollbackPlan:
    """``lkg_present`` historically meant LKG file on disk; callers may pass True when any prior snapshot exists."""

    wants = decision == "blocked" and rollback_allowed and auto_rollback_enabled and lkg_present
    return RollbackPlan(
        dry_run_requested=not live_rollback_enabled,
        restore_wininet=wants,
        restore_winhttp=wants and explicit_winhttp_data,
        would_restore_git_or_env=restore_git_npm_env,
        rationale=(
            "lkg_snapshot_restores_config_instead_of_blind_disable",
            "git_npm_env_requires_explicit_operator_flag",
        ),
    )


def proxy_change_audit_jsonl_path(repo_root: Path) -> Path:
    """Unified sink consumed by ``proxy-watch`` / ``proxy-report`` change attribution tooling."""

    return repo_root / "logs" / "proxy_guard.jsonl"


def emit_proxy_change_detected_audit(
    repo_root: Path,
    *,
    diff: dict[str, Any],
    attribution: dict[str, Any],
    decision: dict[str, Any],
    causation: dict[str, Any] | None = None,
    final_causation: dict[str, Any] | None = None,
) -> None:
    """Append one ``proxy_change_detected`` record for an observed HKCU proxy transition.

    Args:
        repo_root: Toolkit root determining ``logs/proxy_guard.jsonl`` location.
        diff: Output of :func:`~src.proxy_guard.wininet_change_diff.diff_wininet_states` (serialized
            as JSON object).
        attribution: Output of :func:`~src.proxy_guard.change_attribution.attribute_proxy_change`.
        decision: Dict shaped like ``{"action": str, "reason": str}`` from watch policy mapping.

    Returns:
        None.

    Side effects:
        Creates ``logs/`` if missing; appends exactly one JSON object as a single line (NDJSON).

    Raises:
        Propagates filesystem errors from ``append_jsonl`` if the volume is not writable.

    Data shape:
        ``timestamp`` uses :func:`~src.core.time_utils.utc_now_iso` (ISO-8601 UTC with ``Z`` /
        offset as implemented there). ``safety_boundary`` literals document non-negotiable operator
        confirmations for rollback outside this call.

    Audit Notes:
        Treat rows as **correlation evidence**—pair with optional Sysmon / Procmon exports when you
        must prove which PID issued the registry write; this line alone does not establish write proof.
    """

    path = proxy_change_audit_jsonl_path(repo_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "schema_version": "1",
        "timestamp": utc_now_iso(),
        "event": "proxy_change_detected",
        "diff": diff,
        "attribution": attribution,
        "decision": decision,
        "safety_boundary": {
            "no_silent_destructive_repair": True,
            "requires_confirmation_for_rollback": True,
        },
    }
    if causation is not None:
        payload["causation"] = causation
    if final_causation is not None:
        payload["final_causation"] = final_causation
        payload["proof_level"] = final_causation.get("proof_level", "OBSERVED_ONLY")
    append_jsonl(path, payload)

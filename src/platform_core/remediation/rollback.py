"""Rollback plan generation — preview-first; no live execution by default.

Module responsibility:
    Assemble the six-part rollback preview package (snapshot, mutation preview, approval
    token, reversible action record, rollback steps, audit row) for policy-gated remediation.

System placement:
    Called by ``src/platform_core/remediation/planner.py`` and
    ``platform_core/policy/classic.py`` (``RemediationPreview.rollback_preview``).
    Live registry restore remains in ``src/proxy_guard/rollback.py`` (opt-in CLI only).

Key invariants:
    * ``dry_run=True`` is the default for all package builders.
    * ``can_execute_rollback`` always returns ``False`` in this module — no live executor.
    * ``ROLLBACK_LIMITATIONS`` is copied onto every preview artifact.

Audit Notes:
    Append preview rows via :func:`append_rollback_audit_record` to ``logs/rollback_audit.jsonl``.
    Compare ``gate_reason`` on execute attempts with operator confirmation logs — successful
    token validation still does not mutate state here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.platform_core.policy.approval import generate_approval_token, validate_approval_token

ROLLBACK_CONFIRMATION_PHRASE = "RESTORE_PROXY_LKG"

ROLLBACK_LIMITATIONS = [
    "Rollback restores captured values only — not a guarantee of safety or full prior state.",
    "Unknown prior PAC, proxy override, or per-user policy may differ after restore.",
    "Rollback preview does not execute registry or network mutations by default.",
    "Rollback success does not prove endpoint compromise is resolved.",
    "Human approval token and typed confirmation are required before any live rollback.",
]


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def capture_pre_change_snapshot(
    *,
    endpoint_id: str,
    incident_id: str,
    evidence: dict[str, Any] | None = None,
    proxy_enable: int | None = None,
    proxy_server: str | None = None,
) -> dict[str, Any]:
    """Capture read-only pre-change evidence snapshot for rollback planning.

    Args:
        endpoint_id: Stable endpoint identifier for audit correlation.
        incident_id: Incident or failure event id linking snapshot to a decision.
        evidence: Optional normalized signal dict (proxy_enable, proxy_server, tiers).
        proxy_enable: WinINET ProxyEnable override when not in ``evidence``.
        proxy_server: WinINET ProxyServer override when not in ``evidence``.

    Returns:
        Snapshot dict with ``snapshot_id``, ``proxy_registry`` fields, ``limitations``,
        and ``read_only: True``. Timestamps are UTC ISO-8601 (``%Y-%m-%dT%H:%M:%SZ``).

    Side effects:
        None — does not read registry or write files.

    Audit Notes:
        Snapshot reflects caller-supplied values only; stale or partial evidence produces
        a rollback plan that may not restore unknown prior PAC or GPO state.
    """
    evidence = evidence or {}
    return {
        "snapshot_id": f"snap-{uuid.uuid4().hex[:12]}",
        "endpoint_id": endpoint_id,
        "incident_id": incident_id,
        "captured_at_utc": _now_iso(),
        "source": "rollback_pre_change_snapshot",
        "proxy_registry": {
            "ProxyEnable": proxy_enable if proxy_enable is not None else evidence.get("proxy_enable"),
            "ProxyServer": proxy_server if proxy_server is not None else evidence.get("proxy_server"),
            "AutoConfigURL": evidence.get("auto_config_url"),
            "ProxyOverride": evidence.get("proxy_override"),
        },
        "evidence_tier": str(evidence.get("evidence_tier", "OBSERVED_ONLY")),
        "limitations": list(ROLLBACK_LIMITATIONS),
        "read_only": True,
    }


def build_proposed_mutation_preview(
    *,
    action_id: str,
    endpoint_id: str,
    dry_run: bool = True,
    mutations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Describe proposed forward mutation (preview only)."""
    default_mutations = [
        {
            "operation": "registry_set",
            "target": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
            "field": "ProxyEnable",
            "value": 0,
            "human": "Disable WinINET proxy (preview)",
        }
    ]
    return {
        "action_id": action_id,
        "endpoint_id": endpoint_id,
        "dry_run": dry_run,
        "mutations": mutations or default_mutations,
        "executed": False,
        "limitations": list(ROLLBACK_LIMITATIONS),
    }


def build_reversible_action_record(
    *,
    action_id: str,
    endpoint_id: str,
    pre_change_snapshot: dict[str, Any],
    approval_token: str,
) -> dict[str, Any]:
    """Record reversible action metadata linking snapshot to approval gate."""
    return {
        "reversible_action_id": f"rev-{uuid.uuid4().hex[:12]}",
        "action_id": action_id,
        "endpoint_id": endpoint_id,
        "pre_change_snapshot_id": pre_change_snapshot.get("snapshot_id"),
        "approval_token_hint": approval_token[:8] + "…" if approval_token else "",
        "requires_typed_confirmation": True,
        "required_confirmation": ROLLBACK_CONFIRMATION_PHRASE,
        "reversible": True,
        "executed": False,
        "created_at_utc": _now_iso(),
        "limitations": list(ROLLBACK_LIMITATIONS),
    }


def build_rollback_plan(
    *,
    action_id: str,
    prior_proxy_enable: int = 1,
    prior_proxy_server: str = "127.0.0.1:8080",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Legacy rollback plan shape — delegates to preview package steps."""
    preview = build_rollback_preview_package(
        endpoint_id="local",
        incident_id="legacy",
        action_id=action_id,
        pre_change_snapshot=capture_pre_change_snapshot(
            endpoint_id="local",
            incident_id="legacy",
            proxy_enable=prior_proxy_enable,
            proxy_server=prior_proxy_server,
        ),
        proposed_mutation=build_proposed_mutation_preview(action_id=action_id, endpoint_id="local", dry_run=dry_run),
        dry_run=dry_run,
    )
    return {
        "action_id": action_id,
        "dry_run": dry_run,
        "description": "Restore prior WinINET proxy registry values from captured snapshot.",
        "steps": preview["rollback_preview"]["steps"],
        "limitations": preview["rollback_preview"]["limitations"],
        "rollback_preview_id": preview["rollback_preview_id"],
    }


def build_rollback_preview_package(
    *,
    endpoint_id: str,
    incident_id: str,
    action_id: str,
    pre_change_snapshot: dict[str, Any],
    proposed_mutation: dict[str, Any],
    dry_run: bool = True,
    approval_token: str = "",
    confirmation_token: str = "",
    typed_confirmation: str = "",
) -> dict[str, Any]:
    """Assemble full preview-first rollback package with audit metadata."""
    token = approval_token or generate_approval_token()
    reversible = build_reversible_action_record(
        action_id=action_id,
        endpoint_id=endpoint_id,
        pre_change_snapshot=pre_change_snapshot,
        approval_token=token,
    )
    rollback_preview_id = f"rbprev-{uuid.uuid4().hex[:12]}"
    rollback_preview = {
        "rollback_preview_id": rollback_preview_id,
        "endpoint_id": endpoint_id,
        "incident_id": incident_id,
        "action_id": action_id,
        "dry_run": dry_run,
        "steps": [
            {
                "step": 1,
                "operation": "registry_restore",
                "target": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                "values": pre_change_snapshot.get("proxy_registry") or {},
                "requires_typed_confirmation": True,
            },
            {
                "step": 2,
                "operation": "validate",
                "description": "Re-run proxy-proof and browser path probes after rollback.",
            },
        ],
        "required_confirmation": ROLLBACK_CONFIRMATION_PHRASE,
        "limitations": list(ROLLBACK_LIMITATIONS),
        "executed": False,
    }
    can_execute, gate_reason = can_execute_rollback(
        dry_run=dry_run,
        confirmation_token=confirmation_token,
        expected_token=token,
        typed_confirmation=typed_confirmation,
        required_phrase=ROLLBACK_CONFIRMATION_PHRASE,
    )
    audit_record = build_rollback_audit_record(
        rollback_preview_id=rollback_preview_id,
        endpoint_id=endpoint_id,
        incident_id=incident_id,
        action_id=action_id,
        event_kind="rollback_preview_generated",
        dry_run=dry_run,
        gate_reason=gate_reason,
        can_execute=can_execute,
    )
    return {
        "rollback_preview_id": rollback_preview_id,
        "endpoint_id": endpoint_id,
        "incident_id": incident_id,
        "action_id": action_id,
        "dry_run": dry_run,
        "pre_change_snapshot": pre_change_snapshot,
        "proposed_mutation_preview": proposed_mutation,
        "human_approval_token": {
            "required": True,
            "expected_token": token,
            "expected_token_hint": token[:8] + "…",
            "provided": bool(confirmation_token),
            "validated": validate_approval_token(confirmation_token, token) if confirmation_token else False,
        },
        "reversible_action_record": reversible,
        "rollback_preview": rollback_preview,
        "rollback_audit_record": audit_record,
        "can_execute_rollback": can_execute,
        "gate_reason": gate_reason,
        "limitations": list(ROLLBACK_LIMITATIONS),
    }


def build_rollback_audit_record(
    *,
    rollback_preview_id: str,
    endpoint_id: str,
    incident_id: str,
    action_id: str,
    event_kind: str = "rollback_preview_generated",
    dry_run: bool = True,
    gate_reason: str = "",
    can_execute: bool = False,
) -> dict[str, Any]:
    """Build rollback audit row (append via :func:`append_rollback_audit_record`)."""
    return {
        "audit_id": f"aud-rb-{uuid.uuid4().hex[:12]}",
        "event_kind": event_kind,
        "rollback_preview_id": rollback_preview_id,
        "endpoint_id": endpoint_id,
        "incident_id": incident_id,
        "action_id": action_id,
        "timestamp_utc": _now_iso(),
        "dry_run": dry_run,
        "executed": False,
        "can_execute": can_execute,
        "gate_reason": gate_reason,
        "policy_decision": "preview_only",
        "limitations": list(ROLLBACK_LIMITATIONS),
        "read_only": True,
    }


def append_rollback_audit_record(
    record: dict[str, Any],
    *,
    path: Path | None = None,
) -> Path:
    """Append rollback audit/preview row to local JSONL (no remote upload)."""
    from src.logging.audit import append_jsonl

    target = path or Path("logs/rollback_audit.jsonl")
    append_jsonl(target, record)
    return target


def can_execute_rollback(
    *,
    dry_run: bool,
    confirmation_token: str,
    expected_token: str,
    typed_confirmation: str,
    required_phrase: str = ROLLBACK_CONFIRMATION_PHRASE,
) -> tuple[bool, str]:
    """Evaluate whether live rollback may proceed (platform core always denies).

    Args:
        dry_run: When ``True``, returns ``(False, "dry_run_default_no_execution")``.
        confirmation_token: Operator-provided approval token.
        expected_token: Token issued at preview time.
        typed_confirmation: Operator-typed phrase; must equal ``required_phrase``.
        required_phrase: Defaults to :data:`ROLLBACK_CONFIRMATION_PHRASE`.

    Returns:
        Tuple of ``(can_execute, gate_reason)``. This module never returns
        ``can_execute=True`` — live restore is disabled in platform core.

    Audit Notes:
        Log ``gate_reason`` on every execute attempt; ``approval_token_missing_or_invalid``
        vs ``typed_confirmation_required`` distinguish policy failures.
    """
    if dry_run:
        return False, "dry_run_default_no_execution"
    if not validate_approval_token(confirmation_token, expected_token):
        return False, "approval_token_missing_or_invalid"
    if typed_confirmation.strip() != required_phrase:
        return False, "typed_confirmation_required"
    return False, "live_rollback_executor_disabled_preview_only"


def attempt_rollback_execute(
    package: dict[str, Any],
    *,
    confirmation_token: str = "",
    typed_confirmation: str = "",
    expected_token: str = "",
    dry_run: bool = True,
) -> dict[str, Any]:
    """Record a rollback execute attempt without mutating endpoint state.

    Args:
        package: Output of :func:`build_rollback_preview_package`.
        confirmation_token: Operator approval token for gate evaluation.
        typed_confirmation: Typed phrase (e.g. ``RESTORE_PROXY_LKG``).
        expected_token: Override when not stored in ``package``.
        dry_run: When ``True``, gate fails with ``dry_run_default_no_execution``.

    Returns:
        Dict with ``executed=False``, ``can_execute``, ``reason``, nested
        ``rollback_audit_record``, and ``limitations``.

    Side effects:
        None on endpoint state. Caller may append ``rollback_audit_record`` to JSONL.

    Audit Notes:
        ``executed`` is always ``False`` here — correlate with ``src/proxy_guard/rollback.py``
        only when operator runs opt-in CLI rollback separately.
    """
    ht = package.get("human_approval_token") or {}
    token = expected_token or str(ht.get("expected_token", ""))
    can_execute, reason = can_execute_rollback(
        dry_run=dry_run,
        confirmation_token=confirmation_token,
        expected_token=token,
        typed_confirmation=typed_confirmation,
    )

    audit = build_rollback_audit_record(
        rollback_preview_id=str(package.get("rollback_preview_id", "")),
        endpoint_id=str(package.get("endpoint_id", "")),
        incident_id=str(package.get("incident_id", "")),
        action_id=str(package.get("action_id", "")),
        event_kind="rollback_execute_attempt",
        dry_run=dry_run,
        gate_reason=reason,
        can_execute=can_execute,
    )
    return {
        "executed": False,
        "dry_run": dry_run,
        "can_execute": can_execute,
        "reason": reason,
        "rollback_audit_record": audit,
        "limitations": list(ROLLBACK_LIMITATIONS),
    }

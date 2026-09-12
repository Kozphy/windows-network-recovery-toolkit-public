"""Safe proxy-disable remediation — dry-run default, JSON structured output.

Module responsibility:
    Gate WinINET proxy disable behind policy evaluation, typed confirmation, snapshot/
    rollback capture, and append-only audit logging.

System placement:
    Invoked by ``cli.cmd_proxy_disable`` and ``latest_evidence_report`` (preview only).

Key invariants:
    * ``dry_run=True`` by default — no registry mutation.
    * Live apply requires ``confirm`` matching ``CONFIRMATION_PHRASE``.
    * Windows-only — returns ``unsupported_platform`` on other OSes.

Side effects:
    * Dry-run: append audit row only.
    * Live apply: HKCU registry mutations, optional snapshot JSONL, verification read.

Idempotency:
    Dry-run is idempotent. Live apply is not — second apply may be no-op if already disabled.

Failure modes:
    Blocked apply when confirmation missing or policy denies; returns ``action_allowed: false``.

Audit Notes:
    * What could go wrong: operator applies on managed machine with required corporate proxy.
    * Detection: ``proxy-disable.jsonl`` rows with ``action_taken`` and ``before``/``after`` views.
    * Recovery: use rollback plan from snapshot JSONL or restore registry from backup.

Engineering Notes:
    Delegates mutation building to ``src.proxy_guard.remediation`` to keep one registry write path.
"""

from __future__ import annotations

import platform
import subprocess
from typing import Any

from src.core.models import registry_with_parsed
from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from src.proxy_guard.parser import parse_proxy_server
from src.proxy_guard.registry import read_proxy_registry
from src.proxy_guard.remediation import (
    CONFIRMATION_PHRASE,
    build_user_proxy_disable_mutations,
    validate_action_confirmation,
)
from src.proxy_guard.repair_snapshots import (
    append_proxy_snapshots_jsonl,
    build_rollback_plan,
    capture_wininet_snapshot,
    merge_snapshot_payload,
)
from src.proxy_guard.verification import verify_proxy_disabled
from src.repair.executor import apply_mutations
from windows_network_toolkit.audit_store import append_audit_dict
from windows_network_toolkit.platform.decision_engine import decide
from windows_network_toolkit.proxy_state import collect_proxy_state_model


def _unsupported() -> dict[str, Any]:
    return {
        "unsupported_platform": True,
        "platform": platform.system(),
        "message": "proxy-disable requires Windows.",
    }


def run_proxy_disable(
    *,
    dry_run: bool = True,
    confirm: str = "",
    clear_server: bool = True,
    clear_autoconfig: bool = True,
    run: Any = None,
    repo_root: Any = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Preview or apply gated WinINET proxy disable.

    Args:
        dry_run: When True (default), return planned changes without registry writes.
        confirm: Typed confirmation token required for live apply.
        clear_server: When True, clear ProxyServer value on apply.
        clear_autoconfig: When True, clear AutoConfigURL on apply.
        run: Injectable subprocess runner for tests.
        repo_root: When set, append pre-apply snapshot JSONL under repo logs.
        **kwargs: Forwarded to policy ``decide`` and state collection.

    Returns:
        Governance-enveloped dict with policy, classification, before/after views, and audit flags.

    Side effects:
        See module docstring — registry mutation only when dry_run=False and confirmation valid.
    """
    if platform.system() != "Windows":
        return _unsupported()

    from windows_network_toolkit.safety import is_demo_mode

    if is_demo_mode():
        dry_run = True

    run_fn = run or subprocess.run
    state = collect_proxy_state_model(run=run_fn, **kwargs)
    policy = decide(
        "DISABLE_WININET_PROXY",
        dry_run=dry_run,
        confirmation=confirm,
        **kwargs,
    )

    mutations, human_lines = build_user_proxy_disable_mutations(
        clear_proxy_server_value=clear_server,
        clear_autoconfig_url=clear_autoconfig,
    )
    requested_fields = ["ProxyEnable"]
    if clear_server:
        requested_fields.append("ProxyServer")
    if clear_autoconfig:
        requested_fields.append("AutoConfigURL")

    decision, reason, _action_model = validate_action_confirmation(
        action_id="disable_wininet_proxy",
        dry_run=dry_run,
        confirmation=confirm,
        requested_registry_fields=requested_fields,
    )

    reg_before = read_proxy_registry(run=run_fn)
    before_view = registry_with_parsed(reg_before, parse_proxy_server(reg_before.proxy_server))

    if dry_run:
        audit_ok, audit_err = append_audit_dict(
            {
                "command": "proxy-disable",
                "action_requested": "DISABLE_WININET_PROXY",
                "action_allowed": False,
                "action_taken": "none",
                "confirmation_used": confirm,
                "observation": state.to_dict(),
                "hypothesis": policy["proof"]["hypothesis"],
                "result": {"dry_run": True, "planned_changes": human_lines},
                "limitations": policy["classification"]["limitations"],
            },
            log_name="proxy-disable.jsonl",
        )
        return attach_governance_envelope(
            {
                "dry_run": True,
                "action_allowed": False,
                "requires_confirmation": True,
                "confirmation_token": CONFIRMATION_PHRASE,
                "planned_changes": human_lines,
                "no_changes_made": True,
                "policy_decision": policy["policy_decision"],
                "classification": policy["classification"],
                "before": before_view,
                "audit_log_written": audit_ok,
                "audit_error": audit_err,
            },
            primary_classification=policy["classification"].get("primary_classification"),
            policy_outcome=policy["policy_decision"].get("outcome"),
            dry_run=True,
            requires_confirmation=True,
        )

    if decision != "ALLOW" or confirm != CONFIRMATION_PHRASE:
        append_audit_dict(
            {
                "command": "proxy-disable",
                "action_requested": "DISABLE_WININET_PROXY",
                "action_allowed": False,
                "action_taken": "blocked",
                "confirmation_used": confirm,
                "result": {"reason": reason, "decision": decision},
                "limitations": ["Typed confirmation required."],
            },
            log_name="proxy-disable.jsonl",
        )
        return attach_governance_envelope(
            {
                "dry_run": False,
                "action_allowed": False,
                "requires_confirmation": True,
                "confirmation_token": CONFIRMATION_PHRASE,
                "reason": reason,
                "no_changes_made": True,
            },
            policy_outcome="REQUIRE_TYPED_CONFIRMATION",
            dry_run=False,
            requires_confirmation=True,
        )

    capture_pre = capture_wininet_snapshot(run=run_fn)
    rollback_plan = build_rollback_plan(capture_pre)
    if repo_root:
        append_proxy_snapshots_jsonl(repo_root, merge_snapshot_payload(capture_pre, rollback_plan))

    apply_mutations(mutations, dry_run=False)
    reg_after = read_proxy_registry(run=run_fn)
    verification = verify_proxy_disabled(reg_after)
    after_view = registry_with_parsed(reg_after, parse_proxy_server(reg_after.proxy_server))

    changes = ["Set WinINET ProxyEnable to 0"]
    if clear_server:
        changes.append("Clear WinINET ProxyServer")
    if clear_autoconfig:
        changes.append("Clear WinINET AutoConfigURL")

    audit_ok, audit_err = append_audit_dict(
        {
            "command": "proxy-disable",
            "action_requested": "DISABLE_WININET_PROXY",
            "action_allowed": True,
            "action_taken": "applied",
            "confirmation_used": confirm,
            "observation": state.to_dict(),
            "result": {"changes_applied": changes, "verification": verification.to_dict()},
            "limitations": policy["classification"]["limitations"],
        },
        log_name="proxy-disable.jsonl",
    )

    return attach_governance_envelope(
        {
            "dry_run": False,
            "action_allowed": True,
            "confirmation_used": confirm,
            "changes_applied": changes,
            "before": before_view,
            "after": after_view,
            "verification": verification.to_dict(),
            "audit_log_written": audit_ok,
            "audit_error": audit_err,
            "no_changes_made": False,
        },
        policy_outcome="ALLOW",
        dry_run=False,
        requires_confirmation=False,
        executed=True,
    )

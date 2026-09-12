"""Audit-grade safety command handlers wired into ``src.cli`` subcommands.

These handlers add four small surfaces on top of existing diagnostics:

* ``proxy restore-lkg`` — typed-confirmation gated WinINET restore from latest known-good snapshot.
* ``proxy config-check`` — read-only proxy configuration audit (Git/npm/WinINET/WinHTTP/env/browser policy).
* ``proxy registry-writer-proof`` — Sysmon / Security 4657 / Procmon CSV registry-writer evidence.
* ``agent next-step`` — bounded planner that suggests the next read-only probe or preview.

All handlers are read-only by default and emit JSON when ``--json`` is provided. They append
audit rows to ``logs/safety_audit.jsonl``.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import uuid
from pathlib import Path
from typing import Any

from evidence.registry_writer_proof import build_registry_writer_proof
from platform_core.agent_planner import plan_next_step
from platform_core.product_contract import get_diagnosis, latest_diagnosis
from proxy_guard.proxy_config_audit import build_proxy_config_audit

from .core.jsonl import append_jsonl as append_jsonl_core
from .core.time_utils import utc_now_iso
from .core.windows_cli import exit_code_if_not_windows
from .proxy_guard.known_good_store import (
    get_latest_named_record,
    iter_named_records,
    snapshot_from_record,
)
from .proxy_guard.remediation import (
    validate_action_confirmation,
)
from .proxy_guard.rollback import (
    build_wininet_restore_argv_list,
)
from .repair.executor import apply_reg_argv_sequences

_RESTORE_LKG_FIELDS: tuple[str, ...] = ("ProxyEnable", "ProxyServer", "AutoConfigURL", "ProxyOverride", "AutoDetect")
_SAFETY_AUDIT_FILE = "safety_audit.jsonl"


def _repo_root(cli: Path | None) -> Path:
    if cli:
        return cli.resolve()
    return Path(__file__).resolve().parent.parent


def _audit_path(repo: Path) -> Path:
    out = repo / "logs" / _SAFETY_AUDIT_FILE
    out.parent.mkdir(parents=True, exist_ok=True)
    return out


def _append_audit(repo: Path, row: dict[str, Any]) -> str:
    payload = {
        "audit_event_id": row.get("audit_event_id") or str(uuid.uuid4()),
        "timestamp": utc_now_iso(),
        **row,
    }
    payload["audit_event_id"] = str(payload["audit_event_id"])
    append_jsonl_core(_audit_path(repo), payload)
    return str(payload["audit_event_id"])


def _latest_lkg_record(repo: Path) -> dict[str, Any] | None:
    """Return the youngest known-good snapshot row across all snapshot names."""

    last: dict[str, Any] | None = None
    for rec in iter_named_records(repo):
        last = rec
    return last


def _emit_payload(payload: dict[str, Any], *, emit_json: bool, summary_lines: list[str]) -> None:
    if emit_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for line in summary_lines:
            print(line)


def cmd_proxy_restore_lkg(args: argparse.Namespace) -> int:
    """Restore HKCU WinINET proxy fields from the latest known-good snapshot via the confirmation gate.

    Defaults to ``dry_run=true``. Live mutation requires the typed phrase
    ``RESTORE_WININET_PROXY_FROM_LKG`` plus an existing snapshot row. Only the WinINET
    fields documented in the allowlist may be touched; WinHTTP, Git, npm, environment,
    firewall, certificates, processes, and adapters are never touched here.
    """

    repo = _repo_root(getattr(args, "repo_root", None))
    emit_json = bool(getattr(args, "emit_json", False))
    name = str(getattr(args, "snapshot_name", "") or "").strip()
    dry_run = bool(getattr(args, "dry_run", True))
    confirmation = str(getattr(args, "confirm_phrase", "") or "")
    requested_fields: tuple[str, ...] = _RESTORE_LKG_FIELDS

    record = (
        get_latest_named_record(repo, name)
        if name
        else _latest_lkg_record(repo)
    )
    snapshot = snapshot_from_record(record)
    if record is None or snapshot is None:
        payload = {
            "action_id": "restore_wininet_proxy_from_lkg",
            "decision": "BLOCK",
            "dry_run": dry_run,
            "mutated": False,
            "reason": "no_lkg_snapshot_available",
            "snapshot_name": name or None,
            "before": None,
            "after": None,
        }
        audit_event_id = _append_audit(
            repo,
            {
                "type": "repair",
                "subtype": "restore_wininet_proxy_from_lkg",
                "event_kind": "blocked_no_lkg_snapshot",
                "action_id": payload["action_id"],
                "decision": "BLOCK",
                "dry_run": dry_run,
                "mutated": False,
                "reason": payload["reason"],
                "snapshot_name": payload["snapshot_name"],
            },
        )
        payload["audit_event_id"] = audit_event_id
        _emit_payload(payload, emit_json=emit_json, summary_lines=["No known-good snapshot found; nothing to restore."])
        return 1

    decision, reason, action_model = validate_action_confirmation(
        action_id="restore_wininet_proxy_from_lkg",
        dry_run=dry_run,
        confirmation=confirmation,
        requested_registry_fields=requested_fields,
    )
    snapshot_payload = snapshot.to_jsonable() if snapshot else {}
    planned_argv = [list(argv) for argv in build_wininet_restore_argv_list(snapshot)]
    base_payload: dict[str, Any] = {
        "action_id": "restore_wininet_proxy_from_lkg",
        "decision": decision,
        "dry_run": dry_run,
        "mutated": False,
        "reason": reason,
        "snapshot_name": str(record.get("name") or ""),
        "snapshot_captured_at": snapshot_payload.get("captured_at"),
        "before": None,
        "after": None,
        "action": action_model.to_dict() if action_model else {"action_id": "restore_wininet_proxy_from_lkg"},
        "planned_action": {
            "human": [f"Restore HKCU WinINET fields {list(requested_fields)} from snapshot."],
            "mutation_argv": planned_argv,
            "requested_registry_fields": list(requested_fields),
        },
    }

    if dry_run or decision != "ALLOW":
        event_kind = "preview_requested" if dry_run else (
            "blocked_missing_confirmation" if reason == "missing_confirmation" else
            "blocked_wrong_confirmation" if reason == "confirmation_mismatch" else
            "blocked_disallowed_action"
        )
        audit_event_id = _append_audit(
            repo,
            {
                "type": "repair",
                "subtype": "restore_wininet_proxy_from_lkg",
                "event_kind": event_kind,
                "action_id": base_payload["action_id"],
                "decision": decision,
                "dry_run": dry_run,
                "mutated": False,
                "reason": reason,
                "snapshot_name": base_payload["snapshot_name"],
                "planned_action": base_payload["planned_action"],
            },
        )
        base_payload["audit_event_id"] = audit_event_id
        _emit_payload(
            base_payload,
            emit_json=emit_json,
            summary_lines=[
                f"restore-lkg decision={decision} reason={reason}",
                "Pass --dry-run false --confirm RESTORE_WININET_PROXY_FROM_LKG to execute.",
            ],
        )
        return 0 if decision == "PREVIEW" else 1

    if (code := exit_code_if_not_windows("proxy restore-lkg --execute")) is not None:
        base_payload.update({"decision": "BLOCK", "reason": "non_windows_platform"})
        audit_event_id = _append_audit(
            repo,
            {
                "type": "repair",
                "subtype": "restore_wininet_proxy_from_lkg",
                "event_kind": "blocked_disallowed_platform",
                "action_id": base_payload["action_id"],
                "decision": "BLOCK",
                "dry_run": False,
                "mutated": False,
                "reason": "non_windows_platform",
            },
        )
        base_payload["audit_event_id"] = audit_event_id
        _emit_payload(base_payload, emit_json=emit_json, summary_lines=["restore-lkg requires Windows for live restore."])
        return code

    reg_rows = apply_reg_argv_sequences(planned_argv, dry_run=False)
    success = all(int(getattr(r, "returncode", 1)) == 0 for r in reg_rows)
    base_payload.update({
        "mutated": success,
        "decision": "ALLOW" if success else "BLOCK",
        "reason": "mutation_applied" if success else "mutation_failed",
        "before": snapshot_payload,
        "results": [
            {"argv": list(getattr(r, "argv", [])), "code": int(getattr(r, "returncode", 1)), "stderr": str(getattr(r, "stderr", "") or ""), "stdout": str(getattr(r, "stdout", "") or "")}
            for r in reg_rows
        ],
    })
    audit_event_id = _append_audit(
        repo,
        {
            "type": "repair",
            "subtype": "restore_wininet_proxy_from_lkg",
            "event_kind": "remediation_success" if success else "remediation_failed",
            "action_id": base_payload["action_id"],
            "decision": base_payload["decision"],
            "dry_run": False,
            "mutated": success,
            "reason": base_payload["reason"],
            "snapshot_name": base_payload["snapshot_name"],
            "planned_action": base_payload["planned_action"],
            "results": base_payload["results"],
            "before": snapshot_payload,
        },
    )
    base_payload["audit_event_id"] = audit_event_id
    _emit_payload(
        base_payload,
        emit_json=emit_json,
        summary_lines=[
            "Applied LKG restore (HKCU WinINET only)" if success else "Restore failed; see logs/safety_audit.jsonl",
        ],
    )
    return 0 if success else 1


def cmd_proxy_config_check(args: argparse.Namespace) -> int:
    """Read-only proxy config audit. Emits ``proxy_config_checks`` + ``findings``."""

    repo = _repo_root(getattr(args, "repo_root", None))
    emit_json = bool(getattr(args, "emit_json", False))

    result = build_proxy_config_audit().to_dict()
    audit_event_id = _append_audit(
        repo,
        {
            "type": "diagnosis",
            "subtype": "proxy_config_check",
            "event_kind": "diagnosis_run",
            "decision": "ALLOW",
            "dry_run": True,
            "mutated": False,
            "reason": "read_only_audit",
            "findings": [f["kind"] for f in result.get("findings") or []],
        },
    )
    payload = {"audit_event_id": audit_event_id, **result}
    if emit_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print("=== Proxy config check (read-only) ===")
        findings = result.get("findings") or []
        if not findings:
            print("No proxy drift findings.")
        for finding in findings:
            print(f"- [{finding['status']}] {finding['kind']}: {finding['reason']}")
        print(f"audit_event_id={audit_event_id}")
    return 0


def cmd_proxy_registry_writer_proof(args: argparse.Namespace) -> int:
    """Read-only registry-writer evidence collection facade."""

    repo = _repo_root(getattr(args, "repo_root", None))
    emit_json = bool(getattr(args, "emit_json", False))
    procmon = getattr(args, "procmon_csv", None)
    since = int(getattr(args, "since_seconds", 120) or 120)

    payload = build_registry_writer_proof(
        since_seconds=since,
        procmon_csv_path=procmon,
        run=subprocess.run,
        platform_name=platform.system(),
    )
    proof = payload.get("registry_writer_proof") or {}
    audit_event_id = _append_audit(
        repo,
        {
            "type": "evidence",
            "subtype": "registry_writer_proof",
            "event_kind": "proof_run",
            "decision": "ALLOW",
            "dry_run": True,
            "mutated": False,
            "reason": "read_only_evidence_query",
            "status": proof.get("status"),
            "evidence_count": len(proof.get("events") or []),
        },
    )
    payload["audit_event_id"] = audit_event_id
    if emit_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"registry_writer_proof.status = {proof.get('status')}")
        print(f"events = {len(proof.get('events') or [])}")
        print(f"limitation = {proof.get('limitation')}")
        print(f"audit_event_id={audit_event_id}")
    return 0


def cmd_agent_next_step(args: argparse.Namespace) -> int:
    """Bounded local agent planner. Recommendation only; never mutates."""

    repo = _repo_root(getattr(args, "repo_root", None))
    emit_json = bool(getattr(args, "emit_json", False))
    goal = str(getattr(args, "goal", "suggest_next_probe") or "suggest_next_probe")
    run_id = str(getattr(args, "run_id", "") or "").strip()

    diag = get_diagnosis(run_id) if run_id else latest_diagnosis()
    plan = plan_next_step(diag, goal=goal)  # type: ignore[arg-type]
    payload = plan.to_dict()
    audit_event_id = _append_audit(
        repo,
        {
            "type": "agent",
            "subtype": "next_step",
            "event_kind": "agent_next_step_requested",
            "decision": "ALLOW",
            "dry_run": True,
            "mutated": False,
            "reason": "recommendation_only_no_mutation",
            "goal": goal,
            "run_id": run_id or None,
            "next_step": payload.get("next_step"),
            "blocked_actions": payload.get("blocked_actions"),
        },
    )
    payload["audit_event_id"] = audit_event_id
    if emit_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"agent next_step={payload['next_step']} confidence={payload['confidence']:.2f}")
        print(f"reason: {payload['reason']}")
        print(f"policy_boundary: {payload['policy_boundary']}")
        print(f"blocked_actions: {', '.join(payload['blocked_actions'])}")
        print(f"audit_event_id={audit_event_id}")
    return 0

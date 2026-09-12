"""CLI handlers for network recovery app-path scenarios.

Module responsibility:
    Wire legacy ``python -m src`` commands: ``diagnose --app chatgpt``, ``preview``,
    ``remediate`` for the chatgpt_app_firewall scenario.

System placement:
    Registered from ``src/cli.py``; writes audit via ``append_network_recovery_audit``.

Key invariants:
    * Live collectors require Windows.
    * ``cmd_diagnose_app`` always runs with dry_run diagnosis (read-only collectors).
    * BLOCK tier never executes in ``cmd_remediate_scenario``.

Side effects:
    * Writes ``reports/last_network_recovery_diagnosis.json`` and appends JSONL on diagnose/remediate.
    * Live remediate may invoke ``remediation_executor`` subprocess commands.

Audit Notes:
    * Review ``logs/network_recovery_events.jsonl`` after remediate.
    * Recovery: use ``preview`` for tier listing without mutation.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from pathlib import Path
from typing import Any

from .audit import append_network_recovery_audit
from .engine import run_scenario_diagnosis
from .models import SCENARIO_CHATGPT_APP_FIREWALL, SignalBundle
from .remediation_executor import (
    CONFIRMATION_PHRASE,
    execute_selected_low_risk_actions,
    select_low_risk_actions,
)


def _repo_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    return Path(__file__).resolve().parents[2]


def _exit_if_not_windows(command: str) -> int | None:
    if platform.system() != "Windows":
        print(f"{command} requires Windows for live collectors.", file=sys.stderr)
        return 2
    return None


def _parse_recovery_feedback(raw: str | None) -> bool | None:
    if raw is None or not str(raw).strip():
        return None
    val = str(raw).strip().lower()
    if val in {"firewall_reset_helped", "true", "yes", "1"}:
        return True
    if val in {"false", "no", "0", "not_helped"}:
        return False
    return None


def _resolve_scenario(raw: str | None) -> str:
    key = (raw or "").strip().lower()
    if key in {SCENARIO_CHATGPT_APP_FIREWALL, "chatgpt", "chatgpt_app_firewall"}:
        return SCENARIO_CHATGPT_APP_FIREWALL
    raise ValueError(f"Unknown scenario: {raw}")


def cmd_diagnose_app(args: argparse.Namespace) -> int:
    """Run app-path scenario diagnosis with collectors + audit JSONL."""
    app = (getattr(args, "app", None) or "").strip().lower()
    if app != "chatgpt":
        print("diagnose --app: supported values: chatgpt", file=sys.stderr)
        return 2
    if (code := _exit_if_not_windows("diagnose --app chatgpt")) is not None:
        return code

    repo = _repo_root(getattr(args, "repo_root", None))
    recovery = _parse_recovery_feedback(getattr(args, "recovery_feedback", None))
    result = run_scenario_diagnosis(
        SCENARIO_CHATGPT_APP_FIREWALL,
        recovery_firewall_reset_helped=recovery,
        dry_run=True,
    )
    audit_path = append_network_recovery_audit(repo, result)
    last_path = repo / "reports" / "last_network_recovery_diagnosis.json"
    last_path.parent.mkdir(parents=True, exist_ok=True)
    last_path.write_text(json.dumps(result.to_audit_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    if getattr(args, "emit_json", False):
        print(json.dumps(result.to_audit_dict(), indent=2, ensure_ascii=False))
    else:
        print(result.human_summary)
        print("")
        print(f"Audit: {audit_path}")
        print(f"Snapshot: {last_path}")
    return 0


def cmd_preview_scenario(args: argparse.Namespace) -> int:
    """Preview remediation tiers for a scenario (read-only)."""
    try:
        scenario = _resolve_scenario(getattr(args, "scenario", None))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    repo = _repo_root(getattr(args, "repo_root", None))
    last_path = repo / "reports" / "last_network_recovery_diagnosis.json"
    recovery = _parse_recovery_feedback(getattr(args, "recovery_feedback", None))

    if last_path.is_file() and recovery is None:
        try:
            blob = json.loads(last_path.read_text(encoding="utf-8"))
            recovery_raw = blob.get("recovery_feedback")
            if isinstance(recovery_raw, bool):
                recovery = recovery_raw
        except json.JSONDecodeError:
            pass

    if platform.system() == "Windows":
        result = run_scenario_diagnosis(scenario, recovery_firewall_reset_helped=recovery, dry_run=True)
    else:
        signals = SignalBundle(
            browser_https_ok=True,
            chatgpt_https_ok=False,
            openai_https_ok=False,
            curl_https_ok=True,
            dns_ok=True,
            wininet_proxy_enable=0,
            wininet_proxy_server=None,
            wininet_auto_config_url=None,
            winhttp_direct_access=True,
            winhttp_loopback_hint=False,
            firewall_profiles_snapshot={},
            localhost_listener_ports=(),
            chatgpt_process_detected=True,
            electron_process_detected=True,
            vpn_adapter_hint=False,
            collector_notes=("fixture: non-Windows preview uses synthetic signals",),
        )
        result = run_scenario_diagnosis(
            scenario,
            signals=signals,
            recovery_firewall_reset_helped=recovery,
            dry_run=True,
            collect_live=False,
        )

    payload = {
        "scenario_id": result.scenario_id,
        "run_id": result.run_id,
        "policy_decision": result.policy_decision,
        "recommended_actions": [a.to_dict() for a in result.recommended_actions],
        "limitations": result.limitations,
    }
    if getattr(args, "emit_json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print("REMEDIATION PREVIEW (dry-run; no mutations)")
        print(f"Scenario: {result.scenario_id}")
        print(f"Policy: {result.policy_decision}")
        for tier in ("low", "medium", "blocked"):
            items = [a for a in result.recommended_actions if a.risk == tier]
            if not items:
                continue
            print(f"\n{tier.upper()}:")
            for a in items:
                print(f"  [{a.policy_decision}] {a.title} — {a.detail}")
                if a.script_or_command_preview:
                    print(f"      preview: {a.script_or_command_preview}")
    return 0


def cmd_remediate_scenario(args: argparse.Namespace) -> int:
    """Remediation path — dry-run by default; BLOCK tier never executes."""
    try:
        scenario = _resolve_scenario(getattr(args, "scenario", None))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    dry_run = bool(getattr(args, "dry_run", True))
    if not dry_run and platform.system() != "Windows":
        print("remediate without --dry-run requires Windows.", file=sys.stderr)
        return 2

    recovery = _parse_recovery_feedback(getattr(args, "recovery_feedback", None))
    repo = _repo_root(getattr(args, "repo_root", None))

    kwargs: dict[str, Any] = {
        "recovery_firewall_reset_helped": recovery,
        "dry_run": dry_run,
    }
    if platform.system() == "Windows":
        result = run_scenario_diagnosis(scenario, **kwargs)
    else:
        signals = SignalBundle(
            browser_https_ok=True,
            chatgpt_https_ok=False,
            openai_https_ok=None,
            curl_https_ok=True,
            dns_ok=True,
            wininet_proxy_enable=0,
            wininet_proxy_server=None,
            wininet_auto_config_url=None,
            winhttp_direct_access=True,
            winhttp_loopback_hint=False,
            firewall_profiles_snapshot={},
            localhost_listener_ports=(),
            chatgpt_process_detected=True,
            electron_process_detected=False,
            vpn_adapter_hint=False,
        )
        result = run_scenario_diagnosis(
            scenario,
            signals=signals,
            collect_live=False,
            **kwargs,
        )

    selected = select_low_risk_actions(result.signals, result.hypotheses)
    confirm = (getattr(args, "confirm_phrase", None) or "").strip()
    remediation = execute_selected_low_risk_actions(
        selected,
        dry_run=dry_run,
        confirm=confirm,
        previews=result.recommended_actions,
    )
    result.remediation_executed = list(remediation.get("executed", []))

    append_network_recovery_audit(repo, result)

    payload = {
        "dry_run": dry_run,
        "confirmation_token": CONFIRMATION_PHRASE,
        "selected_actions": selected,
        "remediation_executed": result.remediation_executed,
        "remediation_results": remediation.get("results", []),
        "recommended_actions": [a.to_dict() for a in result.recommended_actions],
        "policy_decision": result.policy_decision,
    }
    if getattr(args, "emit_json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        mode = "DRY-RUN PREVIEW" if dry_run else "CONFIRMED PREVIEW ONLY"
        print(f"REMEDIATE ({mode}) — scenario {scenario}")
        print("No destructive automatic repair. BLOCK tier actions are never executed.")
        for a in result.recommended_actions:
            if a.policy_decision == "BLOCK":
                print(f"  [BLOCK] {a.action_id}: {a.detail}")
        if dry_run:
            print(
                f"\nRe-run with --dry-run false and --confirm {CONFIRMATION_PHRASE} "
                "for allowlisted LOW actions only."
            )
    return 0

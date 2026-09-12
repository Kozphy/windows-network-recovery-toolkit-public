"""Execute allowlisted LOW-risk ChatGPT scenario remediations with typed confirmation.

Module responsibility:
    Gate and run LOW-risk actions (flush_dns, reset_winhttp_proxy, restart_chatgpt_app)
    after evidence selection. Enforces same typed-confirmation posture as proxy-disable.

System placement:
    Called by ``auto_fix.run_auto_fix_chatgpt`` and ``cli_handlers.cmd_remediate_scenario``.

Key invariants:
    * ``CONFIRMATION_PHRASE`` must match for live apply.
    * ``_BLOCKED_ACTION_IDS`` and MEDIUM previews never execute.
    * Only subprocess argv from allowlisted action map.

Side effects:
    Live apply runs ipconfig, netsh winhttp reset, Stop-Process/Start-Process for ChatGPT.exe.

Idempotency:
    WinHTTP reset and DNS flush are safe to repeat. App restart is disruptive but bounded.

Failure modes:
    Subprocess timeout/OSError captured in per-action result dict; ``ok=False`` on failure.

Audit Notes:
    * Command execution logged in ``remediation_results`` returned to caller and audit JSONL.
    * Recovery: inspect stderr in results; no automatic rollback for DNS/WinHTTP reset.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .models import RankedHypothesis, RemediationActionPreview, SignalBundle

CONFIRMATION_PHRASE = "APPLY_CHATGPT_LOW_RISK"

_LOW_RISK_ACTION_IDS = frozenset({"flush_dns", "reset_winhttp_proxy", "restart_chatgpt_app"})
_BLOCKED_ACTION_IDS = frozenset(
    {
        "disable_firewall",
        "delete_arbitrary_wfp_filters",
        "kill_unknown_processes",
        "delete_certificates",
        "arbitrary_shell",
        "firewall_reset_preview",
        "stale_block_rule_cleanup_preview",
    }
)


def validate_chatgpt_remediation_confirmation(*, dry_run: bool, confirm: str) -> tuple[bool, str]:
    """Return (allowed, reason). Dry-run always allowed; live apply requires typed token."""
    if dry_run:
        return True, "dry_run_preview"
    if confirm.strip() != CONFIRMATION_PHRASE:
        return False, f"Blocked: provide --confirm {CONFIRMATION_PHRASE} for live LOW-risk apply."
    return True, "confirmed"


def select_low_risk_actions(
    signals: SignalBundle,
    hypotheses: list[RankedHypothesis],
) -> list[str]:
    """Choose LOW-risk action ids supported by current signals (no MEDIUM/BLOCK)."""
    needs_fix = signals.chatgpt_https_ok is False or (
        signals.chatgpt_process_detected and signals.chatgpt_https_ok is not True
    )
    if not needs_fix and signals.openai_https_ok is not False:
        return []

    selected: list[str] = []
    primary = hypotheses[0].hypothesis_id if hypotheses else ""

    if signals.dns_ok is False:
        selected.append("flush_dns")

    if signals.winhttp_loopback_hint or (
        primary == "proxy_or_localhost_proxy_interaction"
        and (signals.wininet_proxy_enable == 1 or signals.localhost_listener_ports)
    ):
        selected.append("reset_winhttp_proxy")

    if primary in {"app_cache_or_session_issue", "electron_network_stack_issue"} or (
        signals.chatgpt_process_detected and signals.chatgpt_https_ok is False
    ):
        selected.append("restart_chatgpt_app")

    if signals.chatgpt_https_ok is False and signals.browser_https_ok is True and "flush_dns" not in selected:
        if signals.dns_ok is not True:
            selected.append("flush_dns")

    return list(dict.fromkeys(selected))


def _run_argv(
    argv: list[str],
    *,
    dry_run: bool,
    run: Callable[..., Any],
    timeout: float,
) -> dict[str, Any]:
    if dry_run:
        return {
            "argv": argv,
            "returncode": 0,
            "stdout": "[dry-run] not executed",
            "stderr": "",
            "executed": False,
        }
    try:
        proc = run(argv, capture_output=True, text=True, shell=False, timeout=timeout)
        return {
            "argv": argv,
            "returncode": int(proc.returncode),
            "stdout": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
            "executed": True,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "argv": argv,
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
            "executed": False,
        }


def _chatgpt_exe_candidates() -> list[Path]:
    local = os.environ.get("LOCALAPPDATA", "")
    program_files = os.environ.get("PROGRAMFILES", "")
    return [
        Path(local) / "Programs" / "ChatGPT" / "ChatGPT.exe",
        Path(program_files) / "ChatGPT" / "ChatGPT.exe",
    ]


def _execute_restart_chatgpt_app(
    *,
    dry_run: bool,
    run: Callable[..., Any],
    timeout: float,
) -> dict[str, Any]:
    exe = next((p for p in _chatgpt_exe_candidates() if p.is_file()), None)
    stop_argv = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Stop-Process -Name ChatGPT -ErrorAction SilentlyContinue",
    ]
    stop_result = _run_argv(stop_argv, dry_run=dry_run, run=run, timeout=timeout)
    start_result: dict[str, Any] | None = None
    if exe is not None:
        start_result = _run_argv([str(exe)], dry_run=dry_run, run=run, timeout=timeout)
    return {
        "action_id": "restart_chatgpt_app",
        "stop": stop_result,
        "start": start_result,
        "chatgpt_exe": str(exe) if exe else None,
        "ok": stop_result.get("returncode") == 0 and (start_result is None or start_result.get("returncode") == 0),
    }


def execute_low_risk_action(
    action_id: str,
    *,
    dry_run: bool,
    run: Callable[..., Any] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Run one allowlisted LOW-risk action; BLOCK/MEDIUM ids raise ValueError."""
    if action_id in _BLOCKED_ACTION_IDS:
        raise ValueError(f"Action {action_id} is blocked from automated execution.")
    if action_id not in _LOW_RISK_ACTION_IDS:
        raise ValueError(f"Unknown or unsupported LOW-risk action: {action_id}")

    run_fn = run or subprocess.run
    if action_id == "flush_dns":
        result = _run_argv(["ipconfig", "/flushdns"], dry_run=dry_run, run=run_fn, timeout=timeout)
        return {"action_id": action_id, **result, "ok": result.get("returncode") == 0}
    if action_id == "reset_winhttp_proxy":
        result = _run_argv(
            ["netsh", "winhttp", "reset", "proxy"],
            dry_run=dry_run,
            run=run_fn,
            timeout=timeout,
        )
        return {"action_id": action_id, **result, "ok": result.get("returncode") == 0}
    return _execute_restart_chatgpt_app(dry_run=dry_run, run=run_fn, timeout=timeout)


def execute_selected_low_risk_actions(
    action_ids: list[str],
    *,
    dry_run: bool,
    confirm: str,
    previews: list[RemediationActionPreview] | None = None,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Apply selected LOW-risk actions after confirmation gate (same posture as proxy-disable)."""
    allowed, reason = validate_chatgpt_remediation_confirmation(dry_run=dry_run, confirm=confirm)
    preview_map = {p.action_id: p for p in (previews or [])}
    results: list[dict[str, Any]] = []
    executed_ids: list[str] = []

    for action_id in action_ids:
        if action_id in _BLOCKED_ACTION_IDS:
            results.append(
                {
                    "action_id": action_id,
                    "policy_decision": "BLOCK",
                    "executed": False,
                    "reason": "Blocked tier — never auto-executed.",
                }
            )
            continue

        preview = preview_map.get(action_id)
        if preview is not None and preview.policy_decision == "BLOCK":
            results.append(
                {
                    "action_id": action_id,
                    "policy_decision": "BLOCK",
                    "executed": False,
                    "reason": preview.detail,
                }
            )
            continue
        if preview is not None and preview.risk != "low":
            results.append(
                {
                    "action_id": action_id,
                    "policy_decision": "PREVIEW",
                    "executed": False,
                    "reason": "MEDIUM/HIGH actions require manual review.",
                }
            )
            continue

        if not allowed:
            results.append(
                {
                    "action_id": action_id,
                    "policy_decision": "PREVIEW",
                    "executed": False,
                    "reason": reason,
                }
            )
            continue

        if action_id not in _LOW_RISK_ACTION_IDS:
            results.append(
                {
                    "action_id": action_id,
                    "policy_decision": "PREVIEW",
                    "executed": False,
                    "reason": f"Action {action_id} is not allowlisted for auto-apply.",
                }
            )
            continue

        blob = execute_low_risk_action(action_id, dry_run=dry_run, run=run)
        blob["policy_decision"] = "ALLOW" if not dry_run else "PREVIEW"
        blob["executed"] = bool(blob.get("executed", dry_run is False))
        results.append(blob)
        if blob.get("ok") or dry_run:
            executed_ids.append(action_id)

    return {
        "confirmation_token": CONFIRMATION_PHRASE,
        "dry_run": dry_run,
        "gate_reason": reason,
        "selected": list(action_ids),
        "executed": executed_ids,
        "results": results,
    }

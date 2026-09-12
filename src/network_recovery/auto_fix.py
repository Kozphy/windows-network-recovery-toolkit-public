"""Orchestrate ChatGPT connectivity auto-fix: proxy, diagnose, LOW-risk remediations.

Module responsibility:
    Single entry point for the auto-fix-chatgpt CLI and scripts/auto-fix-chatgpt.ps1
    step 4. Chains proxy guardian, bad-gateway diagnose, scenario diagnosis, and
    evidence-gated LOW-risk command apply.

System placement:
    Invoked by ``windows_network_toolkit.cli.cmd_auto_fix_chatgpt`` and tests.
    Depends on ``proxy_guardian``, ``bad_gateway``, ``engine``, ``remediation_executor``.

Key invariants:
    * ``DEMO_MODE`` forces dry-run (no mutations).
    * Live LOW-risk apply uses ``APPLY_CHATGPT_LOW_RISK`` when confirm omitted.
    * BLOCK/MEDIUM catalog actions are never executed here.

Side effects:
    * May mutate HKCU proxy via guardian; runs ipconfig/netsh/ChatGPT restart when allowed.
    * Writes ``reports/last_network_recovery_diagnosis.json`` and appends audit JSONL.

Idempotency:
    Diagnosis steps are read-only. Repeated LOW-risk commands are generally safe to rerun.

Failure modes:
    Returns ``unsupported_platform`` off Windows. ``outcome=degraded`` when HTTPS probe fails.

Audit Notes:
    * Wrong remediation: review ``logs/network_recovery_events.jsonl`` and step JSON in return payload.
    * Detection: compare pre/post ``post_check_results`` when live apply ran.
    * Recovery: rerun with ``--dry-run true``; use ``src remediate --dry-run false --confirm ...`` for manual path.
"""

from __future__ import annotations

import json
import platform
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from windows_network_toolkit.diagnostics.bad_gateway import run_bad_gateway_diagnose
from windows_network_toolkit.diagnostics.proxy import run_proxy_status
from windows_network_toolkit.proxy_guardian import run_proxy_guardian_once

from .audit import append_network_recovery_audit
from .collectors import collect_signals
from .engine import run_scenario_diagnosis
from .models import SCENARIO_CHATGPT_APP_FIREWALL
from .remediation_executor import (
    CONFIRMATION_PHRASE,
    execute_selected_low_risk_actions,
    select_low_risk_actions,
)


def _repo_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    return Path(__file__).resolve().parents[2]


def run_auto_fix_chatgpt(
    *,
    dry_run: bool = False,
    confirm: str = "",
    skip_proxy_auto_fix: bool = False,
    skip_guardian_install: bool = False,
    chatgpt_url: str = "https://chatgpt.com",
    repo_root: Path | None = None,
    run: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Chain proxy guardian, bad-gateway diagnose, scenario diagnosis, and LOW-risk apply.

    Args:
        dry_run: When True, preview only (forced when DEMO_MODE env is set).
        confirm: Typed token for live LOW-risk apply; defaults to CONFIRMATION_PHRASE when live.
        skip_proxy_auto_fix: Skip proxy-guardian and live proxy-status steps.
        skip_guardian_install: Reserved for PS orchestrator metadata only.
        chatgpt_url: HTTPS URL passed to bad-gateway diagnose.
        repo_root: Repository root for reports and audit paths.
        run: Injectable subprocess runner for tests.

    Returns:
        JSON-serializable result with ``steps``, ``outcome``, ``limitations``, and audit metadata.

    Side effects:
        See module docstring — registry/command mutation only when not dry_run.
    """
    if platform.system() != "Windows":
        return {
            "unsupported_platform": True,
            "platform": platform.system(),
            "message": "auto-fix-chatgpt requires Windows.",
        }

    from windows_network_toolkit.safety import is_demo_mode

    if is_demo_mode():
        dry_run = True

    repo = _repo_root(repo_root)
    run_fn = run or subprocess.run
    effective_confirm = confirm if confirm else (CONFIRMATION_PHRASE if not dry_run else "")
    steps: list[dict[str, Any]] = []

    if not skip_proxy_auto_fix:
        guardian = run_proxy_guardian_once(dry_run=dry_run)
        steps.append({"step": "proxy_guardian", "result": guardian})
        proxy_status = run_proxy_status()
        steps.append({"step": "proxy_status", "result": proxy_status})
    else:
        proxy_status = run_proxy_status()
        steps.append({"step": "proxy_status", "result": proxy_status, "note": "proxy auto-fix skipped"})

    bad_gateway = run_bad_gateway_diagnose(chatgpt_url, dry_run=True)
    steps.append({"step": "bad_gateway_diagnose", "url": chatgpt_url, "result": bad_gateway})

    diagnosis = run_scenario_diagnosis(
        SCENARIO_CHATGPT_APP_FIREWALL,
        dry_run=dry_run,
        collect_live=True,
        run=run_fn,
    )
    last_path = repo / "reports" / "last_network_recovery_diagnosis.json"
    last_path.parent.mkdir(parents=True, exist_ok=True)
    last_path.write_text(json.dumps(diagnosis.to_audit_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    steps.append(
        {
            "step": "chatgpt_scenario_diagnose",
            "run_id": diagnosis.run_id,
            "primary_hypothesis": diagnosis.hypotheses[0].hypothesis_id if diagnosis.hypotheses else None,
            "signals": diagnosis.signals.to_dict(),
            "report_path": str(last_path),
        }
    )

    selected = select_low_risk_actions(diagnosis.signals, diagnosis.hypotheses)
    remediation = execute_selected_low_risk_actions(
        selected,
        dry_run=dry_run,
        confirm=effective_confirm,
        previews=diagnosis.recommended_actions,
        run=run_fn,
    )
    diagnosis.remediation_executed = list(remediation.get("executed", []))
    steps.append({"step": "low_risk_remediation", "result": remediation})

    if not dry_run and diagnosis.remediation_executed:
        post_signals = collect_signals(run=run_fn)
        diagnosis.post_check_results = {
            "chatgpt_https_ok": post_signals.chatgpt_https_ok,
            "openai_https_ok": post_signals.openai_https_ok,
            "browser_https_ok": post_signals.browser_https_ok,
            "dns_ok": post_signals.dns_ok,
        }
        steps.append({"step": "post_check", "result": diagnosis.post_check_results})

    append_network_recovery_audit(repo, diagnosis)

    classification = str(proxy_status.get("classification") or "")
    chatgpt_ok = diagnosis.signals.chatgpt_https_ok
    outcome = "healthy"
    if chatgpt_ok is False or classification == "DEAD_PROXY_CONFIG":
        outcome = "degraded"
    elif chatgpt_ok is None:
        outcome = "inconclusive"

    return {
        "dry_run": dry_run,
        "skip_proxy_auto_fix": skip_proxy_auto_fix,
        "skip_guardian_install": skip_guardian_install,
        "confirmation_token": CONFIRMATION_PHRASE,
        "outcome": outcome,
        "proxy_classification": classification,
        "chatgpt_https_ok": chatgpt_ok,
        "steps": steps,
        "diagnosis_run_id": diagnosis.run_id,
        "limitations": diagnosis.limitations,
    }

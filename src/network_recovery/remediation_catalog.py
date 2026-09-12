"""Preview-gated remediation catalog for chatgpt_app_firewall scenario.

Module responsibility:
    Enumerate BLOCK, MEDIUM, and LOW remediation tiers as ``RemediationActionPreview`` rows.

System placement:
    Used by ``engine.run_scenario_diagnosis``; execution delegated to ``remediation_executor``.

Key invariants:
    * BLOCK actions always ``policy_decision=BLOCK``.
    * MEDIUM always PREVIEW-only (``dry_run_only=True``).
    * LOW ALLOW only when ``dry_run=False`` in catalog (still requires confirm at execute).

Audit Notes:
    * Catalog describes intent only; executor enforces allowlist at apply time.
"""

from __future__ import annotations

from .models import RemediationActionPreview

# BLOCK tier — never auto-executed; policy BLOCK
_BLOCKED: tuple[tuple[str, str, str], ...] = (
    ("disable_firewall", "Disable Windows Firewall", "Disabling firewall is blocked from automated remediation."),
    (
        "delete_arbitrary_wfp_filters",
        "Delete arbitrary WFP filters",
        "Bulk WFP filter deletion is blocked; requires manual security review.",
    ),
    ("kill_unknown_processes", "Kill unknown processes", "Process termination is blocked without explicit forensic workflow."),
    ("delete_certificates", "Delete certificates", "Certificate deletion is blocked from this toolkit."),
    ("arbitrary_shell", "Arbitrary shell execution", "Free-form shell is blocked from API/CLI remediation paths."),
)

# MEDIUM — preview only
_MEDIUM: tuple[tuple[str, str, str | None], ...] = (
    (
        "firewall_reset_preview",
        "Firewall reset (preview)",
        "Preview only: restores default firewall policy — review rules after; does not prove malicious activity.",
        r"scripts\reset_firewall.bat",
    ),
    (
        "stale_block_rule_cleanup_preview",
        "Stale block rule cleanup (preview)",
        "Preview only: inspect outbound block rules affecting ChatGPT/Electron paths in Windows Defender Firewall.",
        None,
    ),
)

# LOW — ALLOW with operator confirmation when not dry-run
_LOW: tuple[tuple[str, str, str | None], ...] = (
    ("flush_dns", "Flush DNS cache", "Low risk: ipconfig /flushdns (preview by default).", r"scripts\reset_dns.bat"),
    (
        "reset_winhttp_proxy",
        "Reset WinHTTP proxy to direct",
        "Low risk: netsh winhttp reset proxy (does not change WinINET user proxy).",
        None,
    ),
    (
        "restart_chatgpt_app",
        "Restart ChatGPT desktop app",
        "Low risk: close and relaunch ChatGPT.exe — does not kill arbitrary processes.",
        None,
    ),
)


def remediation_previews_for_chatgpt_scenario(*, dry_run: bool) -> list[RemediationActionPreview]:
    """Return tiered remediation previews; ``dry_run`` forces preview-only semantics."""
    out: list[RemediationActionPreview] = []
    for action_id, title, detail in _BLOCKED:
        out.append(
            RemediationActionPreview(
                action_id=action_id,
                title=title,
                risk="blocked",
                policy_decision="BLOCK",
                dry_run_only=True,
                detail=detail,
                script_or_command_preview=None,
            )
        )
    for action_id, title, detail, script in _MEDIUM:
        out.append(
            RemediationActionPreview(
                action_id=action_id,
                title=title,
                risk="medium",
                policy_decision="PREVIEW",
                dry_run_only=True,
                detail=detail,
                script_or_command_preview=script,
            )
        )
    for action_id, title, detail, script in _LOW:
        out.append(
            RemediationActionPreview(
                action_id=action_id,
                title=title,
                risk="low",
                policy_decision="PREVIEW" if dry_run else "ALLOW",
                dry_run_only=dry_run,
                detail=detail,
                script_or_command_preview=script,
            )
        )
    return out

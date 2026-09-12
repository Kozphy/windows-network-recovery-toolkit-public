"""Document src.attribution.suspicious_process responsibilities.

Module responsibility:
    Owns attribution helpers that connect process evidence to observed network or proxy changes without asserting causal certainty beyond available evidence.

System placement:
    Used by CLI, API, or platform services that assemble endpoint evidence and governance outputs.

Key invariants:
    Keeps observations, hypotheses, policy decisions, remediation, and audit records separate.

Side effects:
    Importing this module has no intended runtime side effects beyond defining constants, classes, or functions.
"""

from __future__ import annotations

_LOW_BENIGN = frozenset(
    {
        "svchost.exe",
        "lsass.exe",
        "services.exe",
        "wininit.exe",
        "csrss.exe",
        "smss.exe",
        "winlogon.exe",
        "spoolsv.exe",
    },
)
_MEDIUM_NAMES = frozenset(
    {
        "node.exe",
        "python.exe",
        "python3.exe",
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "code.exe",
        "cursor.exe",
        "electron.exe",
    },
)


def diagnostic_suspicion_tier(
    process_name: str | None,
    *,
    localhost_proxy_owner: bool,
    command_line_unavailable: bool,
) -> str:
    """Return ``low``, ``medium``, or ``high`` for operator messaging (never 'malware').

    high:
        localhost proxy attribution with missing CLI or medium-tier interpreter parent.
    """
    name_l = (process_name or "").lower()
    if not name_l:
        return "medium" if localhost_proxy_owner else "low"
    if name_l in _LOW_BENIGN and not localhost_proxy_owner:
        return "low"
    if name_l in _MEDIUM_NAMES or localhost_proxy_owner:
        hi = localhost_proxy_owner and (command_line_unavailable or name_l in _MEDIUM_NAMES)
        if hi:
            return "high"
        return "medium"
    # Unknown tooling / unfamiliar binary name
    if localhost_proxy_owner:
        return "high" if command_line_unavailable else "medium"
    return "medium"

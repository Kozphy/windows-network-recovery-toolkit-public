"""Structured ``reg.exe`` argv previews for disabling WinINET user proxy keys.

WinHTTP reset stays out-of-scope deliberately; callers must document that externally.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

INTERNET_SETTINGS_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_INTERNET_SETTINGS_KEY = INTERNET_SETTINGS_KEY


CONFIRMATION_PHRASE = "DISABLE_WININET_PROXY"
RESTORE_WININET_PROXY_FROM_LKG_PHRASE = "RESTORE_WININET_PROXY_FROM_LKG"
STOP_PROXY_LISTENER_PHRASE = "STOP_PROXY_LISTENER"
STOP_PROXY_REVERTER_PHRASE = "STOP_PROXY_REVERTER"

RiskLevel = Literal["low", "medium", "high", "blocked"]
Decision = Literal["ALLOW", "PREVIEW", "BLOCK"]


@dataclass(frozen=True)
class AllowlistedRemediationAction:
    """Policy row for one state-changing remediation action.

    The model is intentionally small and local. It describes which action IDs are
    known, which typed phrase is required before mutation, which registry values
    may be changed, whether the action is reversible, and why dangerous actions
    are blocked.
    """

    action_id: str
    description: str
    risk_level: RiskLevel
    required_confirmation: str
    allowed_registry_fields: tuple[str, ...]
    reversible: bool
    blocked_reason: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe projection for audit rows and API responses."""

        return {
            "action_id": self.action_id,
            "description": self.description,
            "risk_level": self.risk_level,
            "required_confirmation": self.required_confirmation,
            "allowed_registry_fields": list(self.allowed_registry_fields),
            "reversible": self.reversible,
            "blocked_reason": self.blocked_reason,
        }


_ALLOWLIST: dict[str, AllowlistedRemediationAction] = {
    "disable_wininet_proxy": AllowlistedRemediationAction(
        action_id="disable_wininet_proxy",
        description="Disable the current user's WinINET proxy by setting HKCU ProxyEnable to 0.",
        risk_level="medium",
        required_confirmation=CONFIRMATION_PHRASE,
        allowed_registry_fields=("ProxyEnable", "ProxyServer", "AutoConfigURL"),
        reversible=True,
    ),
    "restore_wininet_proxy_from_lkg": AllowlistedRemediationAction(
        action_id="restore_wininet_proxy_from_lkg",
        description="Restore targeted HKCU WinINET proxy fields from a last-known-good snapshot.",
        risk_level="medium",
        required_confirmation=RESTORE_WININET_PROXY_FROM_LKG_PHRASE,
        allowed_registry_fields=("ProxyEnable", "ProxyServer", "AutoConfigURL", "ProxyOverride", "AutoDetect"),
        reversible=True,
    ),
    "stop_proxy_listener": AllowlistedRemediationAction(
        action_id="stop_proxy_listener",
        description=(
            "Terminate the process tree listening on the attributed localhost WinINET proxy port "
            "(operator-confirmed; Administrator required)."
        ),
        risk_level="high",
        required_confirmation=STOP_PROXY_LISTENER_PHRASE,
        allowed_registry_fields=(),
        reversible=False,
    ),
    "stop_proxy_reverter": AllowlistedRemediationAction(
        action_id="stop_proxy_reverter",
        description=(
            "Terminate the attributed parent powershell.exe process tree that respawns the "
            "localhost proxy listener (operator-confirmed; Administrator required; manual only)."
        ),
        risk_level="high",
        required_confirmation=STOP_PROXY_REVERTER_PHRASE,
        allowed_registry_fields=(),
        reversible=False,
    ),
    "reset_firewall": AllowlistedRemediationAction(
        action_id="reset_firewall",
        description="Firewall reset is not allowed from proxy remediation.",
        risk_level="blocked",
        required_confirmation="",
        allowed_registry_fields=(),
        reversible=False,
        blocked_reason="firewall reset is blocked from automatic remediation",
    ),
    "disable_adapter": AllowlistedRemediationAction(
        action_id="disable_adapter",
        description="Adapter disable is not allowed from proxy remediation.",
        risk_level="blocked",
        required_confirmation="",
        allowed_registry_fields=(),
        reversible=False,
        blocked_reason="adapter disable is blocked from automatic remediation",
    ),
    "kill_process": AllowlistedRemediationAction(
        action_id="kill_process",
        description="Process kill is not allowed from proxy remediation.",
        risk_level="blocked",
        required_confirmation="",
        allowed_registry_fields=(),
        reversible=False,
        blocked_reason="process kill is blocked from automatic remediation",
    ),
    "delete_certificate": AllowlistedRemediationAction(
        action_id="delete_certificate",
        description="Certificate deletion is not allowed from proxy remediation.",
        risk_level="blocked",
        required_confirmation="",
        allowed_registry_fields=(),
        reversible=False,
        blocked_reason="certificate deletion is blocked from automatic remediation",
    ),
    "broad_registry_cleanup": AllowlistedRemediationAction(
        action_id="broad_registry_cleanup",
        description="Broad registry cleanup is not allowed from proxy remediation.",
        risk_level="blocked",
        required_confirmation="",
        allowed_registry_fields=(),
        reversible=False,
        blocked_reason="broad registry cleanup is blocked from automatic remediation",
    ),
}


@dataclass(frozen=True)
class ProxyDisableMutation:
    """Single ``reg.exe`` invocation (argument vector, no shell)."""

    argv: tuple[str, ...]
    human: str


def remediation_action_catalog() -> tuple[AllowlistedRemediationAction, ...]:
    """Return all remediation action rows, including blocked dangerous actions."""

    return tuple(_ALLOWLIST.values())


def get_remediation_action(action_id: str) -> AllowlistedRemediationAction | None:
    """Return the allowlist row for ``action_id`` when known."""

    return _ALLOWLIST.get(action_id)


def validate_action_confirmation(
    *,
    action_id: str,
    dry_run: bool,
    confirmation: str,
    requested_registry_fields: tuple[str, ...],
) -> tuple[Decision, str, AllowlistedRemediationAction | None]:
    """Evaluate whether an action may execute.

    Preview remains read-only. Live mutation requires a known non-blocked action,
    a requested field set within the action's allowlist, and the exact typed
    confirmation phrase.
    """

    action = get_remediation_action(action_id)
    if action is None:
        return "BLOCK", "unknown_action", None
    if action.blocked_reason:
        return "BLOCK", action.blocked_reason, action
    not_allowed = sorted(set(requested_registry_fields) - set(action.allowed_registry_fields))
    if not_allowed:
        return "BLOCK", f"registry_fields_not_allowlisted:{','.join(not_allowed)}", action
    if dry_run:
        return "PREVIEW", "dry_run_preview_only", action
    if not confirmation.strip():
        return "BLOCK", "missing_confirmation", action
    if confirmation.strip() != action.required_confirmation:
        return "BLOCK", "confirmation_mismatch", action
    return "ALLOW", "confirmed_allowlisted_action", action


def build_user_proxy_disable_mutations(
    *,
    clear_proxy_server_value: bool,
    clear_autoconfig_url: bool = True,
) -> tuple[tuple[ProxyDisableMutation, ...], tuple[str, ...]]:
    """Preview WinINET HKCU clears aligned with ``scripts/reset_proxy.bat`` (HKCU scope).

    WinHTTP remains untouched deliberately (use ``reset_proxy.bat`` for WinHTTP).
    """
    lines: list[str] = []
    mutations: list[ProxyDisableMutation] = []

    m1 = ProxyDisableMutation(
        argv=(
            "reg",
            "add",
            _INTERNET_SETTINGS_KEY,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ),
        human=f'reg add "{_INTERNET_SETTINGS_KEY}" /v ProxyEnable /t REG_DWORD /d 0 /f',
    )
    mutations.append(m1)
    lines.append(m1.human)

    if clear_proxy_server_value:
        m2 = ProxyDisableMutation(
            argv=(
                "reg",
                "delete",
                _INTERNET_SETTINGS_KEY,
                "/v",
                "ProxyServer",
                "/f",
            ),
            human=f'reg delete "{_INTERNET_SETTINGS_KEY}" /v ProxyServer /f',
        )
        mutations.append(m2)
        lines.append(m2.human)

    if clear_autoconfig_url:
        m3 = ProxyDisableMutation(
            argv=(
                "reg",
                "delete",
                _INTERNET_SETTINGS_KEY,
                "/v",
                "AutoConfigURL",
                "/f",
            ),
            human=f'reg delete "{_INTERNET_SETTINGS_KEY}" /v AutoConfigURL /f',
        )
        mutations.append(m3)
        lines.append(m3.human)

    warnings = (
        "This modifies only HKCU WinINET proxy values; WinHTTP is unchanged.",
        "Software that reapplies proxy policy may restore these keys after logout or schedule.",
    )
    return tuple(mutations), tuple(lines + list(warnings))

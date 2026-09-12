"""HKCU proxy transition policy for Proxy Guard.

Ranks consecutive :class:`~src.proxy_guard.models.ProxySnapshot` probes into
:class:`~src.proxy_guard.models.ProxyGuardPolicyDecision` (**allowed**, **blocked**,
**observe**) using PAC allowlists, attribution mode, localhost listener probes, and
process allowlists from :mod:`~src.proxy_guard.policy`. Sits in the guard pipeline after
snapshots diff and attribution resolution (see :mod:`~src.proxy_guard.guard`).

Key invariants:
    * Suspicious PAC and loopback edits default toward **blocked** when not explicitly trusted.
    * ``hkcu_proxy_core_tuple`` defines which WinINET columns gate "no-op" early exit.
    * Attribution verdicts are **hints** unless ``verified_eventlog`` satisfies policy hooks.

Raises:
    This module intentionally avoids raising during evaluation; unexpected ``None``
    snapshots should be prevented by callers upstream.

Audit Notes:
    Decisions propagate to structured pipeline audit sinks. Mis-tuned JSON policy can
    over-block (rollback storms) or over-observe (silent drift). Compare control JSONL
    timestamps against ``proxy-snapshot diff`` output and reconcile
    ``config/proxy_guard_policy.json`` against ``shared/proxy_guard_policy.example.json``.
"""

from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Any

from .models import AttributionResult, ProxyGuardPolicyDecision, ProxySnapshot
from .parser import ParsedProxy
from .pipeline import disabling_transition_allowed
from .policy import PolicyDecision, ProxyGuardPolicy
from .proxy_path_operational import ProxyPathOperationalAssessment


def hkcu_proxy_core_tuple(snapshot: ProxySnapshot) -> tuple[Any, ...]:
    """Return a comparable tuple of user-visible HKCU WinINET fields.

    Enables detecting meaningful registry transitions while ignoring unrelated probe
    fields (for example Git or WinHTTP narration) unless those fields also changed elsewhere.

    Args:
        snapshot: Point-in-time join that includes HKCU-derived columns.

    Returns:
        ``(proxy_enable, proxy_server, proxy_override, auto_config_url, auto_detect)``.
    """
    return (
        snapshot.proxy_enable,
        snapshot.proxy_server,
        snapshot.proxy_override,
        snapshot.auto_config_url,
        snapshot.auto_detect,
    )


def _norm_str(val: str | None) -> str:
    return (val or "").strip()


def _exe_basename_candidate(process_exe: str | None, process_name: str | None) -> str | None:
    """Lowercase basename for whitelist checks; tolerant of quoted Win32 paths."""
    if process_exe:
        try:
            return PureWindowsPath(process_exe.strip().strip('"')).name.lower()
        except ValueError:
            pass
    if process_name:
        return str(process_name).lower()
    return None


def exe_path_trusted(candidate_path: str | None, prefixes: tuple[str, ...]) -> bool:
    """Return True when ``candidate_path`` is prefixed by administrator trust roots.

    Args:
        candidate_path: Executable image path resolved by attribution (possibly quoted).
        prefixes: Absolute path prefixes normalized to lowercase backslashes.

    Returns:
        True if ``candidate_path`` nestles under any non-empty normalized prefix.

    Constraints:
        Compares lexical prefix only; symbolic links across roots are intentionally ignored.
    """
    if not candidate_path or not prefixes:
        return False
    norm = candidate_path.strip().strip('"').lower().replace("/", "\\")
    for pref in prefixes:
        root = pref.strip().strip('"').lower().replace("/", "\\").rstrip("\\")
        if not root:
            continue
        if norm.startswith(root):
            return True
    return False


def attribution_to_owner_rows(attribution: AttributionResult) -> list[dict[str, Any]]:
    """Convert :class:`~src.proxy_guard.models.AttributionResult` into policy rows.

    Downstream substring allowlists expect ``process_name`` + ``pid`` keys mirroring probe
    owner rows.

    Args:
        attribution: Event-log or heuristic identity bundle produced by attribution layer.

    Returns:
        Zero or one row dictionaries suitable for ``ProxyGuardPolicy.evaluate``.
    """
    if attribution.process is None:
        return []
    proc = attribution.process
    basename = _exe_basename_candidate(proc.exe, proc.name)
    if not basename:
        return []
    return [{"process_name": basename, "pid": proc.pid}]


def evaluate_proxy_transition(
    *,
    prior_snap: ProxySnapshot,
    curr_snap: ProxySnapshot,
    parsed_prior: ParsedProxy,
    parsed_after: ParsedProxy,
    attribution: AttributionResult,
    policy: ProxyGuardPolicy,
    port_listen: bool | None,
    path_assessment: ProxyPathOperationalAssessment | None = None,
) -> ProxyGuardPolicyDecision:
    """Classify a WinINET-facing transition with guarded defaults.

    Args:
        prior_snap: HKCU-aligned snapshot captured before polling interval.
        curr_snap: HKCU-aligned snapshot captured after polling interval.
        parsed_prior: Parser output prior to detection (unused for branching today but kept symmetric for audits).
        parsed_after: Parsed ``ProxyServer`` after change.
        attribution: Resolved identity/mode/confidence tuple for the suspicion context.
        policy: Loaded Proxy Guard policy defining allow/block substrings + paths.
        port_listen:
            Tri-state loopback probe: ``True`` listener present, ``False`` absent, ``None`` unknown.
        path_assessment:
            Optional operational path assessment (listener + HTTPS contrast). When present,
            loopback branches prefer path operability over ``ProxyEnable`` alone.

    Returns:
        :class:`~src.proxy_guard.models.ProxyGuardPolicyDecision` including rollback hints.

    Side effects:
        None (pure classification).

    Engineering Notes:
        ``observe_only_when_unknown_attribution`` trades automatic rollback friction for noisy
        environments lacking Sysmon/EventLog corroboration.
    """

    core_before = hkcu_proxy_core_tuple(prior_snap)
    core_after = hkcu_proxy_core_tuple(curr_snap)
    if core_before == core_after:
        return ProxyGuardPolicyDecision(
            decision="observe",
            reason="no_op_registry_core",
            matched_rule=None,
            rollback_allowed=False,
            rollback_required=False,
        )

    if disabling_transition_allowed(prior_snap, curr_snap):
        return ProxyGuardPolicyDecision(
            decision="allowed",
            reason="proxy_disable_transition_allowed_default",
            matched_rule=None,
            rollback_allowed=False,
            rollback_required=False,
        )

    pac_prev = _norm_str(prior_snap.auto_config_url)
    pac_curr = _norm_str(curr_snap.auto_config_url)
    if pac_prev != pac_curr and pac_curr:
        subs = getattr(policy, "allowed_autoconfig_url_substrings", ())
        matched_rule: str | None = None
        for s in subs:
            if str(s).lower() in pac_curr.lower():
                matched_rule = f"allow_autoconfig_substring:{s}"
                break
        if matched_rule is None:
            return ProxyGuardPolicyDecision(
                decision="blocked",
                reason="autoconfig_url_change_not_allowlisted",
                matched_rule=None,
                rollback_allowed=True,
                rollback_required=False,
            )

    if attribution.mode == "verified_eventlog" and attribution.process is not None:
        if exe_path_trusted(attribution.process.exe, getattr(policy, "trusted_exe_paths", ())):
            return ProxyGuardPolicyDecision(
                decision="allowed",
                reason="trusted_exe_path_verified_eventlog",
                matched_rule="trusted_exe_paths",
                rollback_allowed=False,
                rollback_required=False,
            )

    if parsed_after.is_localhost_proxy:
        if path_assessment is not None:
            if path_assessment.composite_state == "LOOPBACK_BROKEN":
                return ProxyGuardPolicyDecision(
                    decision="blocked",
                    reason="loopback_proxy_path_non_operational",
                    matched_rule="proxy_path_operational",
                    rollback_allowed=True,
                    rollback_required=False,
                )
            if path_assessment.composite_state == "LOOPBACK_OPERATIONAL":
                return ProxyGuardPolicyDecision(
                    decision="allowed",
                    reason="loopback_path_operational_observe",
                    matched_rule="proxy_path_operational",
                    rollback_allowed=False,
                    rollback_required=False,
                )

        base_rows = attribution_to_owner_rows(attribution)
        pd_name: PolicyDecision = policy.evaluate(base_rows)
        trusted_path = attribution.process is not None and exe_path_trusted(
            attribution.process.exe,
            getattr(policy, "trusted_exe_paths", ()),
        )
        verified_event = attribution.mode == "verified_eventlog"
        listener_ok = port_listen is True
        if listener_ok or trusted_path or verified_event or pd_name.allowed:
            rule = pd_name.matched_rule or ("localhost_listener_present" if listener_ok else "trusted_override")
            return ProxyGuardPolicyDecision(
                decision="allowed",
                reason="localhost_loopback_policy_allow",
                matched_rule=str(rule),
                rollback_allowed=False,
                rollback_required=False,
            )
        if port_listen is False:
            return ProxyGuardPolicyDecision(
                decision="blocked",
                reason="loopback_proxy_without_listener_and_untrusted",
                matched_rule=None,
                rollback_allowed=True,
                rollback_required=False,
            )

    pd = policy.evaluate(attribution_to_owner_rows(attribution))
    if pd.allowed:
        return ProxyGuardPolicyDecision(
            decision="allowed",
            reason=pd.reason,
            matched_rule=pd.matched_rule,
            rollback_allowed=False,
            rollback_required=False,
        )

    if policy.observe_only_when_unknown_attribution and (
        attribution.mode == "unknown" or attribution.process is None
    ):
        return ProxyGuardPolicyDecision(
            decision="observe",
            reason="observe_only_unknown_attribution_user_manual_mode",
            matched_rule=None,
            rollback_allowed=False,
            rollback_required=False,
        )

    return ProxyGuardPolicyDecision(
        decision="blocked",
        reason=pd.reason,
        matched_rule=None,
        rollback_allowed=True,
        rollback_required=False,
    )

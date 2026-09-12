"""Canonical remediation allowlist for the Endpoint Reliability Platform.

This module defines the single source of truth for named remediation actions: risk tier,
typed confirmation phrases, optional ``scripts/*.bat`` basenames, deployment surface rules,
and whether the HTTP API may spawn a subprocess for an action.

System placement:
    ``FailureEvent`` and operator intent flow into :func:`get_remediation_action` and
    :func:`canonical_action_name`. :mod:`platform_core.policy` reads summaries derived here;
    :mod:`platform_core.remediation` uses basename sets from :func:`list_script_basenames`.
    ``backend.platform_routes`` gates ``POST /platform/remediation/execute`` against these
    definitions.

Key invariants:
    * ``forbidden`` and appropriately flagged ``high`` entries do not authorize API-bound
      repair (additional denial lives in :mod:`platform_core.policy` and routes).
    * :data:`_ACTION_ALIASES` maps legacy action strings to canonical registry keys without
      duplicating :class:`RemediationActionDef` rows.
    * :class:`RemediationActionDef` is frozen so registry rows are immutable at runtime.

Engineering notes:
    The registry is code, not YAML/JSON, so changes are reviewable in PRs, type-checked,
    and avoid parse cost at import. ``manual_only=True`` with ``api_execute_allowed=False``
    marks runbook-only repair, distinct from ``forbidden`` (explicitly disallowed patterns).

Audit notes:
    Widening ``api_execute_allowed`` or weakening confirmation phrases increases blast radius;
    catch via code review and :mod:`tests`. Recovery is redeploy or revert—no migration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

RiskName = Literal["read_only", "low", "medium", "high", "forbidden"]
Surface = Literal["api", "cli", "dashboard"]


@dataclass(frozen=True)
class RemediationActionDef:
    """Immutable safety metadata for one operator-facing remediation primitive.

    Encodes blast-radius and surface rules so policy, audit, and preview UIs can evaluate
    an action without opening batch file contents.

    Key attributes map to API/CLI identifiers, optional script basenames, risk tier, where
    the action may be invoked, and gating for live execution vs dry-run or manual-only.

    Interacts with :func:`get_remediation_action` (construction source), :mod:`policy`
    (preview and execute decisions), and ``backend`` execution validation.

    Engineering notes:
        ``frozen=True`` prevents accidental mutation; update the registry or construct a
        new instance when definitions change.

    Audit notes:
        If ``script_path`` does not match a file under ``scripts/``, executors return allowlist
        errors—verify filesystem layout after registry edits.

    Attributes:
        action_name: Stable key used in previews and execution requests (post-alias).
        script_path: Basename under repository ``scripts/`` when a subprocess models repair;
            ``None`` for read-only or manual-only entries without a script.
        risk_level: Coarse tier from ``read_only`` through ``forbidden``; fused with
            ``RemediationPolicy.allowed_risk_levels`` in policy.
        allowed_surfaces: Where preview/execute may originate; empty tuple blocks all surfaces.
        api_execute_allowed: Whether ``POST /platform/remediation/execute`` may run a subprocess
            when other policy checks pass.
        requires_confirmation: Whether operator flow must record human acknowledgment when
            paired with org policy.
        confirmation_phrase: Exact typed token for phrase gates; empty if no typed gate.
        dry_run_allowed: Whether dry-run execution records are meaningful (``False`` for
            forbidden actions).
        manual_only: When ``True``, live repair is not delegated via API subprocess.
        rollback_plan: Human-readable rollback hint for previews; never executed by this module.

    Raises:
        None from the dataclass itself; structural errors surface as typical ``TypeError`` /
            ``dataclass`` init failures if callers construct invalid combinations.
    """

    action_name: str
    script_path: str | None
    risk_level: RiskName
    allowed_surfaces: tuple[Surface, ...]
    api_execute_allowed: bool
    requires_confirmation: bool
    confirmation_phrase: str
    dry_run_allowed: bool
    manual_only: bool
    rollback_plan: str


def _all_surfaces() -> tuple[Surface, ...]:
    """Return the tuple of every supported remediation caller surface.

    Supplies a shared ``("api", "cli", "dashboard")`` literal for benign registry rows so
    adding or removing a surface is a single-code-path change.

    Decision intent:
        Avoid copying the same triple across dozens of definitions and reduce review drift.

    Input assumptions:
        None (no parameters).

    Output guarantees:
        Always ``("api", "cli", "dashboard")``, same object identity pattern per call site
        (tuple of three string literals).

    Side effects:
        None.

    Idempotency:
        Pure; repeated calls yield equal values.

    Returns:
        Tuple of surface names usable in ``RemediationActionDef.allowed_surfaces``.

    Raises:
        Nothing.

    Example:
        >>> _all_surfaces()
        ('api', 'cli', 'dashboard')
    """

    return ("api", "cli", "dashboard")


# Canonical registry keys match stable API / CLI action strings.
_REMEDIATION_REGISTRY: dict[str, RemediationActionDef] = {
    "inspect_proxy": RemediationActionDef(
        action_name="inspect_proxy",
        script_path=None,
        risk_level="read_only",
        allowed_surfaces=_all_surfaces(),
        api_execute_allowed=False,
        requires_confirmation=False,
        confirmation_phrase="",
        dry_run_allowed=True,
        manual_only=False,
        rollback_plan="N/A (read-only inspection).",
    ),
    "preview_dns_flush": RemediationActionDef(
        action_name="preview_dns_flush",
        script_path=None,
        risk_level="read_only",
        allowed_surfaces=_all_surfaces(),
        api_execute_allowed=False,
        requires_confirmation=False,
        confirmation_phrase="",
        dry_run_allowed=True,
        manual_only=False,
        rollback_plan="N/A (preview only).",
    ),
    "export_report": RemediationActionDef(
        action_name="export_report",
        script_path=None,
        risk_level="read_only",
        allowed_surfaces=_all_surfaces(),
        api_execute_allowed=False,
        requires_confirmation=False,
        confirmation_phrase="",
        dry_run_allowed=True,
        manual_only=False,
        rollback_plan="Re-run collector; reports are non-destructive.",
    ),
    "reset_dns": RemediationActionDef(
        action_name="reset_dns",
        script_path="reset_dns.bat",
        risk_level="medium",
        allowed_surfaces=_all_surfaces(),
        api_execute_allowed=True,
        requires_confirmation=True,
        confirmation_phrase="RUN_DNS_RESET",
        dry_run_allowed=True,
        manual_only=False,
        rollback_plan="Restore prior DNS servers from backup notes if applicable.",
    ),
    "reset_proxy": RemediationActionDef(
        action_name="reset_proxy",
        script_path="reset_proxy.bat",
        risk_level="medium",
        allowed_surfaces=_all_surfaces(),
        api_execute_allowed=True,
        requires_confirmation=True,
        confirmation_phrase="RUN_PROXY_RESET",
        dry_run_allowed=True,
        manual_only=False,
        rollback_plan="Reconfigure WinHTTP/user proxy per policy documentation.",
    ),
    "stop_proxy_listener": RemediationActionDef(
        action_name="stop_proxy_listener",
        script_path=None,
        risk_level="high",
        allowed_surfaces=("cli",),
        api_execute_allowed=False,
        requires_confirmation=True,
        confirmation_phrase="STOP_PROXY_LISTENER",
        dry_run_allowed=True,
        manual_only=True,
        rollback_plan="Process termination is not reversible; restart dev tooling manually if needed.",
    ),
    "stop_proxy_reverter": RemediationActionDef(
        action_name="stop_proxy_reverter",
        script_path=None,
        risk_level="high",
        allowed_surfaces=("cli",),
        api_execute_allowed=False,
        requires_confirmation=True,
        confirmation_phrase="STOP_PROXY_REVERTER",
        dry_run_allowed=True,
        manual_only=True,
        rollback_plan=(
            "Parent powershell termination is not reversible; restart dev proxy scripts manually if needed."
        ),
    ),
    "winsock_reset": RemediationActionDef(
        action_name="winsock_reset",
        script_path=None,
        risk_level="medium",
        allowed_surfaces=_all_surfaces(),
        api_execute_allowed=False,
        requires_confirmation=True,
        confirmation_phrase="RUN_WINSOCK_RESET",
        dry_run_allowed=True,
        manual_only=True,
        rollback_plan="Requires reboot planning; follow enterprise change windows.",
    ),
    "tcpip_reset": RemediationActionDef(
        action_name="tcpip_reset",
        script_path=None,
        risk_level="medium",
        allowed_surfaces=_all_surfaces(),
        api_execute_allowed=False,
        requires_confirmation=True,
        confirmation_phrase="RUN_TCPIP_RESET",
        dry_run_allowed=True,
        manual_only=True,
        rollback_plan="Document interface settings before stack reset.",
    ),
    "firewall_reset_manual_only": RemediationActionDef(
        action_name="firewall_reset_manual_only",
        script_path="reset_firewall.bat",
        risk_level="high",
        allowed_surfaces=_all_surfaces(),
        api_execute_allowed=False,
        requires_confirmation=True,
        confirmation_phrase="RUN_FIREWALL_RESET",
        dry_run_allowed=True,
        manual_only=True,
        rollback_plan="Manual restore of firewall profiles from backup or GPO.",
    ),
    "arbitrary_command_forbidden": RemediationActionDef(
        action_name="arbitrary_command_forbidden",
        script_path=None,
        risk_level="forbidden",
        allowed_surfaces=(),
        api_execute_allowed=False,
        requires_confirmation=False,
        confirmation_phrase="",
        dry_run_allowed=False,
        manual_only=False,
        rollback_plan="Not applicable.",
    ),
    "adapter_disable_forbidden": RemediationActionDef(
        action_name="adapter_disable_forbidden",
        script_path=None,
        risk_level="forbidden",
        allowed_surfaces=(),
        api_execute_allowed=False,
        requires_confirmation=False,
        confirmation_phrase="",
        dry_run_allowed=False,
        manual_only=False,
        rollback_plan="Not applicable.",
    ),
    "process_kill_forbidden": RemediationActionDef(
        action_name="process_kill_forbidden",
        script_path=None,
        risk_level="forbidden",
        allowed_surfaces=(),
        api_execute_allowed=False,
        requires_confirmation=False,
        confirmation_phrase="",
        dry_run_allowed=False,
        manual_only=False,
        rollback_plan="Not applicable.",
    ),
    "certificate_delete_forbidden": RemediationActionDef(
        action_name="certificate_delete_forbidden",
        script_path=None,
        risk_level="forbidden",
        allowed_surfaces=(),
        api_execute_allowed=False,
        requires_confirmation=False,
        confirmation_phrase="",
        dry_run_allowed=False,
        manual_only=False,
        rollback_plan="Not applicable.",
    ),
}


# Legacy / CLI aliases → canonical registry keys (backward compatibility).
_ACTION_ALIASES: dict[str, str] = {
    "reset_winsock": "winsock_reset",
    "reset_tcpip": "tcpip_reset",
    "reset_firewall": "firewall_reset_manual_only",
    "arbitrary_command": "arbitrary_command_forbidden",
    "arbitrary_command_forbidden": "arbitrary_command_forbidden",
    "process_kill": "process_kill_forbidden",
    "kill_process": "process_kill_forbidden",
    "certificate_delete": "certificate_delete_forbidden",
    "delete_certificate": "certificate_delete_forbidden",
}


def canonical_action_name(action_name: str) -> str:
    """Resolve a remediation label to its canonical registry key.

    Translates historically stable alias strings into the authoritative key stored in
    :data:`_REMEDIATION_REGISTRY`, so lookups and policy evaluation reference one row per
    logical action.

    Decision intent:
        Keep a single remediation definition when external strings evolve (rename keys or
        split actions) without duplicated :class:`RemediationActionDef` instances.

    Constraints / limitations:
        Does not validate that the resolved key exists; pair with :func:`get_remediation_action`.

    Known failure modes:
        Callers treating any return value as defined may mis-handle unknown keys—always
        follow with a registry lookup.

    Input assumptions:
        ``action_name`` is trimmed by callers; leading/trailing whitespace is not stripped here.

    Output guarantees:
        If ``action_name`` is in :data:`_ACTION_ALIASES`, returns the mapped target; otherwise
        returns ``action_name`` unchanged.

    Side effects:
        None.

    Idempotency:
        For any alias chain expressible by one hop, applying twice yields the same result as
        once; canonical keys map to themselves.

    Args:
        action_name: Raw remediation identifier from CLI, HTTP body, or policy.

    Returns:
        Canonical registry key suitable for ``_REMEDIATION_REGISTRY.get``. May still be
        absent from the registry if unknown.

    Raises:
        Nothing.

    Example:
        >>> canonical_action_name("reset_firewall") == "firewall_reset_manual_only"
        True
    """

    return _ACTION_ALIASES.get(action_name, action_name)


def get_remediation_action(action_name: str) -> RemediationActionDef | None:
    """Fetch frozen remediation metadata for an external action identifier.

    Resolves aliases via :func:`canonical_action_name`, then performs a dictionary lookup into
    the built-in registry—the primary read path for previews, risk evaluation, and execute
    gating downstream.

    Decision intent:
        Centralize "what metadata applies to this string?" so routes and policy do not fork
        alias logic.

    Constraints / limitations:
        Unknown identifiers return ``None``. Callers (:mod:`policy`) map that outcome to an
        ``unknown_action`` (or equivalent) denial path rather than inferring defaults.

    Known failure modes:
        Stale tests or dashboards sending deprecated strings without aliases yield ``None``;
        mitigate by extending :data:`_ACTION_ALIASES` or updating callers.

    Input assumptions:
        ``action_name`` is treated as opaque UTF-8 string; callers supply stable lowercase
        identifiers in practice—no timezone or schema normalization here.

    Output guarantees:
        Returns the exact :class:`RemediationActionDef` instance from the registry for the
        canonical key when present.

    Side effects:
        None.

    Idempotency:
        Read-only; identical inputs yield identical outputs for a given deployment.

    Args:
        action_name: External remediation key, possibly an alias such as ``reset_firewall``.

    Returns:
        Matching frozen definition when the canonical key exists; otherwise ``None``.

    Raises:
        Nothing.

    Example:
        >>> get_remediation_action("inspect_proxy") is not None
        True
        >>> get_remediation_action("not_a_real_action") is None
        True
    """

    key = canonical_action_name(action_name)
    return _REMEDIATION_REGISTRY.get(key)


def list_script_basenames() -> frozenset[str]:
    """Return every distinct ``scripts/*.bat`` basename tied to scripted repair definitions.

    Scans registry values for ``script_path`` entries that are not ``None``, collecting
    basenames subprocess allowlisting uses (:mod:`platform_core.remediation`).

    Input assumptions:
        ``script_path`` values are stored as filenames only (no directories), enforced by how
        the registry was authored—not validated at runtime beyond truthiness checks.

    Output guarantees:
        Result is immutable; duplicates collapse to one element; membership deterministic for current
        :data:`_REMEDIATION_REGISTRY`. Order within the ``frozenset`` is unspecified.

    Side effects:
        None.

    Idempotency:
        Deterministic pure function across calls for the same module state.

    Returns:
        ``frozenset`` of script basenames referenced by automate-able repair definitions.

    Raises:
        Nothing.

    Engineering notes:
        Linear scan of small dict O(n)—portfolio-scale registry cardinality.

    Audit notes:
        If paths slip in containing directory separators, allowlist matchers may mismatch
        filenames—enforce basename-only authoring in reviews.

    Example:
        >>> "reset_dns.bat" in list_script_basenames()
        True
    """

    out: set[str] = set()
    for d in _REMEDIATION_REGISTRY.values():
        if d.script_path:
            out.add(d.script_path)
    return frozenset(out)


def to_policy_meta(defn: RemediationActionDef) -> dict[str, object]:
    """Serialize a remediation definition into the legacy plain-dict projection.

    Builds the ``risk``, ``script``, ``phrase``, and related keys expected by transitional
    helpers still iterating string-key blobs in :mod:`platform_core.policy` and tests—bridges
    the dataclass-first registry without mutating callers in one refactor.

    Input assumptions:
        ``defn`` is frozen and complete; callers do not mutate the returned dictionary.

    Output guarantees:
        Shallow mapping with primitive or tuple values (`risk`, `script`, `phrase`,
        `allowed_surfaces`, `api_execute_allowed`, `manual_only`) suitable for comparison and
        JSON-compatible logging payloads.

    Side effects:
        Allocates one new dictionary per call.

    Idempotency:
        Same ``defn`` always yields identical field-wise content until code changes registry.

    Args:
        defn: Frozen row from :func:`get_remediation_action`.

    Returns:
        Dictionary keyed by legacy field names consumed by older policy integrations.

    Raises:
        Nothing.

    Example:
        >>> d = get_remediation_action("reset_dns")
        >>> to_policy_meta(d)["phrase"] == "RUN_DNS_RESET"
        True
    """

    return {
        "risk": defn.risk_level,
        "script": defn.script_path,
        "phrase": defn.confirmation_phrase,
        "allowed_surfaces": defn.allowed_surfaces,
        "api_execute_allowed": defn.api_execute_allowed,
        "manual_only": defn.manual_only,
    }


def build_action_registry_legacy_dict() -> dict[str, dict[str, object]]:
    """Build flatten alias-expanded dict for transitional ``ACTION_REGISTRY`` wiring.

    Produces ``dict[name, legacy_meta]`` including every canonical key and every alias in
    :data:`_ACTION_ALIASES`, each projected through :func:`to_policy_meta` so ``policy.ACTION_REGISTRY``
    can be assigned from a single import-time constant without divergence between aliases and canonical names.

    Decision intent:
        Preserve backwards-compatible dict iteration in policy while the canonical registry
        remains the authoring surface—prevents silently divergent metadata for aliases.

    Constraints / limitations:
        Rebuild new dict allocation each invocation; suited for module import/tests, not hot loops.

    Known failure modes:
        If aliases pointed at unknown targets, omitted rows would silently drop alias keys;
        current authoring keeps aliases valid—detect breakage via tests asserting presence of
        expected alias keys.

    Input assumptions:
        Backed exclusively by loaded module globals; no external data or clock.

    Output guarantees:
        Every canonical registry key maps to legacy meta every alias duplicates its target meta;
        alphabetical key order unspecified.

    Side effects:
        None beyond allocation.

    Idempotency:
        Deterministic for fixed module globals until redeploy reloads the module.

    Returns:
        ``dict`` suitable for assigning ``policy.ACTION_REGISTRY`` in shim paths.

    Raises:
        Nothing.

    Engineering notes:
        Prefer :func:`get_remediation_action` in new surfaces; reserve this shim for legacy
        policy constants and dashboards.

    Audit notes:
        If shim and :data:`_REMEDIATION_REGISTRY` desync during refactors—tests should trip;
        recovery is aligning alias map and regenerate this dict at import.

    Example:
        >>> reg = build_action_registry_legacy_dict()
        >>> reg["reset_firewall"] == reg["firewall_reset_manual_only"]
        True
    """

    flat: dict[str, dict[str, object]] = {}
    for key, defn in _REMEDIATION_REGISTRY.items():
        flat[key] = to_policy_meta(defn)
    for alias, target in _ACTION_ALIASES.items():
        base = _REMEDIATION_REGISTRY.get(target)
        if base:
            flat[alias] = to_policy_meta(base)
    return flat

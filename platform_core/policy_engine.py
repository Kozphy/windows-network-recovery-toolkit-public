"""High-level policy router for Endpoint Reliability Platform demos.

Module responsibility:
    Project :func:`~platform_core.policy.evaluate` (:class:`~platform_core.policy.StructuredPolicyDecision`) into
    short **verb** labels for UX copy and portfolio narration, and optionally fuse optional JSON **hints** about
    localhost proxy posture without weakening registry-backed forbid rules.

System placement:
    Sits beside :mod:`platform_core.policy.classic` (ACTION_REGISTRY gates) and :mod:`platform_core.remediation_registry`.
    FastAPI routes continue to call classic helpers directly—this module is **additive** for dashboards/tests.

Key invariants:
    * ``high`` / ``forbidden`` remediation tiers always coerce the verb to ``block`` even when previews might exist.
    * ``applied_rules`` strings are diagnostic tags only—they do **not** bypass RBAC or typed confirmation in routers.

Input assumptions:
    ``signal_bundle`` may include ``proxy_server``, ``unsigned_path_hint``, ``rollback_context``, ``summary`` keys
    used only for ``applied_rules`` tagging.

Output guarantees:
    Tuple ``(verb, detail_dict)`` where ``detail_dict`` contains ``structured`` (full decision dump) and
    ``applied_rules`` (string tags).

Side effects:
    :func:`load_policy_hints` reads JSON from disk when path exists (stdlib only).

Failure modes:
    Malformed JSON in hint files raises :exc:`json.JSONDecodeError`—callers should catch in interactive demos.

Audit Notes:
    Verbs summarize policy posture only—actual **execute** remains gated in ``backend.platform_routes`` with
    dry-run defaults and allowlisted scripts; reconcile ``detail_dict["structured"]["reason_codes"]`` with
    ``platform_data/audit.jsonl`` when operators dispute UI wording.

Engineering Notes:
    Hint bundles stay JSON for zero extra dependencies; YAML mirrors exist for human editing only until a loader is wired.

See Also:
    ``docs/rbac_and_remediation.md``.

Decision verbs map to remediation posture:
    * ``allow`` — structured evaluation produced ``execute_allowed=True`` (still subject to route confirmation).
    * ``alert`` — neither preview nor execute is permitted under current structured gate (viewer-like denial paths).
    * ``block`` — forbidden/high-tier or substring ``forbidden`` reason codes tripped forced deny.
    * ``preview_only`` — previews allowed; live execute false until admin + confirmation elsewhere.
    * ``require_confirmation`` — confirmation phrases required per registry before subprocess spawn.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from platform_core.policy import OperatorContext, SignalSnapshot
from platform_core.policy import evaluate as evaluate_structured

PlatformDecisionVerb = Literal["allow", "alert", "block", "preview_only", "require_confirmation"]


@dataclass(frozen=True)
class PlatformPolicyHints:
    """Declarative knobs mirrored from optional JSON bundles (see ``config/platform_policy.example.json``).

    Attributes:
        allow_developer_proxy_ports: Loopback ports treated as benign developer proxies when matched in ``proxy_server`` text.
        localhost_proxy_requires_alert: When true, emit ``unknown_localhost_proxy`` tag for loopback literals.
        unsigned_path_alert_only: When true, emit ``unsigned_suspicious_path`` when ``unsigned_path_hint`` is truthy.
        rollback_requires_confirmation: When true, emit ``rollback_confirmation_required`` if ``rollback_context`` present.

    Constraints:
        Tags influence ``applied_rules`` only—they never widen execution permission beyond :mod:`platform_core.policy`.
    """

    allow_developer_proxy_ports: list[int]
    localhost_proxy_requires_alert: bool
    unsigned_path_alert_only: bool
    rollback_requires_confirmation: bool


DEFAULT_HINTS = PlatformPolicyHints(
    allow_developer_proxy_ports=[7890, 8888],
    localhost_proxy_requires_alert=True,
    unsigned_path_alert_only=True,
    rollback_requires_confirmation=True,
)


def load_policy_hints(path: str | Path | None) -> PlatformPolicyHints:
    """Hydrate hints from JSON on disk — missing path or file yields :data:`DEFAULT_HINTS`.

    Args:
        path: Optional filesystem path to JSON with keys matching portfolio examples.

    Returns:
        Frozen :class:`PlatformPolicyHints`.

    Raises:
        json.JSONDecodeError: When file exists but JSON is invalid.

    Side effects:
        Reads file once per call (no caching).

    Idempotency:
        Pure relative to disk contents—identical files yield identical structs.
    """
    if not path:
        return DEFAULT_HINTS
    p = Path(path)
    if not p.is_file():
        return DEFAULT_HINTS
    raw = json.loads(p.read_text(encoding="utf-8"))
    ports = (
        raw.get("developer_proxy_allowlist_ports") or raw.get("allow_developer_proxy_ports") or []
    )
    return PlatformPolicyHints(
        allow_developer_proxy_ports=[int(x) for x in ports],
        localhost_proxy_requires_alert=bool(raw.get("localhost_proxy_requires_alert", True)),
        unsigned_path_alert_only=bool(raw.get("unsigned_path_alert_only", True)),
        rollback_requires_confirmation=bool(raw.get("rollback_requires_confirmation", True)),
    )


def _verb_from_structured(
    exec_allowed: bool, preview_allowed: bool, reason_codes: list[str]
) -> PlatformDecisionVerb:
    if any("forbidden" in r or "arbitrary" in r for r in reason_codes):
        return "block"
    if exec_allowed:
        return "allow"
    if preview_allowed and any("confirmation" in r for r in reason_codes):
        return "require_confirmation"
    if preview_allowed:
        return "preview_only"
    return "alert"


def evaluate_route_decision(
    *,
    remediation_action: str | None,
    operator_role: str,
    surface: Literal["api", "cli", "dashboard"] = "api",
    signal_bundle: dict[str, Any] | None = None,
    hints: PlatformPolicyHints | None = None,
) -> tuple[PlatformDecisionVerb, dict[str, Any]]:
    """Return ``(verb, detail_dict)`` fusing structured policy + heuristic signal tagging.

    Args:
        remediation_action: Registry key forwarded to :func:`~platform_core.policy.evaluate` after canonicalization.
        operator_role: Portfolio role string accepted by :class:`~platform_core.policy.OperatorContext` (e.g. ``admin``).
        surface: Ingress channel hint for classic policy evaluation.
        signal_bundle: Optional telemetry snippets used solely for ``applied_rules`` tagging.
        hints: Optional declarative bundle; defaults to :data:`DEFAULT_HINTS`.

    Returns:
        Tuple of UI verb plus ``{"structured": StructuredPolicyDecision dict, "applied_rules": list[str]}``.

    Raises:
        None intentionally—invalid roles propagate via structured ``reason_codes`` inside ``structured``.

    Side effects:
        None (pure evaluation aside from structured policy internals).

    Audit Notes:
        Compare ``structured["reason_codes"]`` with FastAPI ``403`` responses when debugging mismatched verbs—the
        router remains authoritative for HTTP enforcement.
    """
    hc = hints or DEFAULT_HINTS
    applied_rules: list[str] = []

    bundle = dict(signal_bundle or {})

    prox = str(bundle.get("proxy_server") or "").lower()
    if "127.0.0.1" in prox or "localhost" in prox:
        if hc.localhost_proxy_requires_alert:
            applied_rules.append("unknown_localhost_proxy")

    ports = hc.allow_developer_proxy_ports
    for p in ports:
        if prox.endswith(f":{p}") or f":{p}" in prox:
            applied_rules.append("developer_proxy_allowlisted")

    if bundle.get("unsigned_path_hint"):
        applied_rules.append("unsigned_suspicious_path")

    if bundle.get("rollback_context"):
        if hc.rollback_requires_confirmation:
            applied_rules.append("rollback_confirmation_required")

    ctx = OperatorContext(role=operator_role, surface=surface)  # type: ignore[arg-type]
    sd = evaluate_structured(
        SignalSnapshot(summary=str(bundle.get("summary") or "")),
        remediation_action,
        ctx,
    )

    verb = _verb_from_structured(sd.execute_allowed, sd.preview_allowed, sd.reason_codes)

    if (
        sd.risk_tier in {"high", "forbidden"}
        or "execute_blocked_high_or_forbidden_tier" in sd.reason_codes
    ):
        applied_rules.append("high_risk_blocked")
        if verb != "block":
            verb = "block"

    return verb, {"structured": sd.model_dump(), "applied_rules": applied_rules}

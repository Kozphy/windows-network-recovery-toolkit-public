"""Drift normalization for Network State compare flows.

Delegates structural diff equality to :func:`~src.proxy_guard.known_good_diff.diff_snapshots`, then stacks
deterministic heuristic flags (:func:`detect_suspicious_cases`) and optional advisory policy overlays from
:class:`NetworkStatePolicy`.

Key invariants:
    * Outputs are JSON-serializable dicts destined for CLI / reports.
    * Suspicion markers are advisory — they **do not** assert malware or authorship.

Raises:
    None from public helpers; malformed ``ProxySnapshot`` inputs should surface earlier during hydration.

Audit Notes:
    Callers emitting ``network_state_events`` should include trimmed payloads only (baseline label,
    suspicion counts); avoid dumping full snapshots into JSONL tails.

See Also:
    ``python -m src network-state diff``.
"""

from __future__ import annotations

import re
from typing import Any

from ..proxy_guard.known_good_diff import diff_snapshots as base_diff_snapshots
from ..proxy_guard.models import ProxySnapshot
from ..proxy_guard.parser import ParsedProxy, parse_proxy_server
from .policy import NetworkStatePolicy, evaluate_network_state_policy


def _empty(val: Any) -> bool:
    return val is None or (isinstance(val, str) and val.strip() == "")


def detect_suspicious_cases(saved: ProxySnapshot, current: ProxySnapshot, changed_fields: dict[str, Any]) -> list[str]:
    """Enumerate advisory transition codes for tooling and policy correlation.

    ``changed_fields`` mirrors :func:`~src.proxy_guard.known_good_diff.diff_snapshots` output for future
    expansion; today heuristics also compare snapshots directly for clarity.

    Args:
        saved: Baseline labeled profile capture.
        current: Latest live capture identical schema.
        changed_fields: Redundant structural map retained for callers passing precomputed deltas.

    Returns:
        Sorted unique string codes (ASCII snake tokens).

    Side effects:
        None.

    Constraints:
        Regex loopback heuristics target ``127.0.0.1`` / ``localhost`` / ``::1`` substrings only;
        other literal forms may omit ``proxy_server_loopback_port_pattern``.
    """
    _ = changed_fields

    flags: list[str] = []

    if saved.proxy_enable == 0 and current.proxy_enable == 1:
        flags.append("proxy_enable_escalated_off_to_on")

    ss = str(saved.proxy_server or "")
    cs = str(current.proxy_server or "")
    if ss != cs and re.search(r"127\.0\.0\.1:\d+|localhost:\d+", cs, re.I):
        flags.append("proxy_server_loopback_port_pattern")

    sa = str(saved.auto_config_url or "").strip()
    ca = str(current.auto_config_url or "").strip()
    if _empty(sa) and not _empty(ca):
        flags.append("auto_config_url_newly_set")

    tool_pairs = (
        ("git_http_proxy", saved.git_http_proxy, current.git_http_proxy),
        ("git_https_proxy", saved.git_https_proxy, current.git_https_proxy),
        ("npm_proxy", saved.npm_proxy, current.npm_proxy),
        ("npm_https_proxy", saved.npm_https_proxy, current.npm_https_proxy),
        ("user_http_proxy", saved.user_http_proxy, current.user_http_proxy),
        ("user_https_proxy", saved.user_https_proxy, current.user_https_proxy),
        ("user_all_proxy", saved.user_all_proxy, current.user_all_proxy),
    )
    for label, a, b in tool_pairs:
        if _empty(a) and not _empty(b):
            flags.append(f"{label}_proxy_suddenly_added")

    return sorted(set(flags))


def drift_bundle(
    saved: ProxySnapshot,
    current: ProxySnapshot,
    *,
    policy: NetworkStatePolicy | None,
    attribution_heuristic: dict[str, Any] | None,
) -> dict[str, Any]:
    """Produce diff + suspicion markers + optional policy verdict for telemetry export.

    Args:
        saved: Named baseline capture.
        current: Latest capture evaluated on operator workstation.
        policy: Parsed policy JSON or defaults; ``None`` suppresses overlays.
        attribution_heuristic:
            Loose owner rows (for example ``{"owners":[{"process_name":...}]}``).

    Returns:
        Dict with keys:
            * ``changed_fields`` — structural deltas.
            * ``suspicious_loopback_hints`` — parser-level hints propagated from Proxy Guard diff.
            * ``suspicious_cases`` — Network State heuristic codes.
            * ``policy`` — mapping from ``evaluate_network_state_policy`` or ``None``.
            * ``attribution_note`` — constant reminder text for downstream consumers.

    Side effects:
        None.

    Raises:
        None.
    """
    base = base_diff_snapshots(saved, current)
    changed = base.get("changed_fields") or {}
    suspicions = detect_suspicious_cases(saved, current, changed)

    parsed: ParsedProxy = parse_proxy_server(current.proxy_server)
    policy_out = (
        evaluate_network_state_policy(policy, parsed=parsed, suspicions=suspicions, attribution=attribution_heuristic)
        if policy is not None
        else None
    )

    return {
        "changed_fields": changed,
        "suspicious_loopback_hints": base.get("suspicious_loopback_hints") or [],
        "suspicious_cases": suspicions,
        "policy": policy_out,
        "attribution_note": "Heuristic attribution only — not forensic proof.",
    }

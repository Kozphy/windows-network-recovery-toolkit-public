"""Drift classification between successive :mod:`proxy_guard.state` snapshots.

Module responsibility:
    Compare scalar WinINET-aligned keys extracted from snapshots, derive ``changed_fields`` using PascalCase
    registry-facing labels, and attach qualitative ``risk_level`` / ``reason`` strings for alerting + JSONL.

System placement:
    Called from ``proxy-watch`` after each poll; outputs feed policy decisions and append-only auditing.

Input assumptions:
    * ``before`` and ``after`` originate from :func:`~src.proxy_guard.state.snapshot_wininet_state`; missing
      optional keys behave like ``None`` comparisons.

Output guarantees:
    * When ``changed`` is false, ``risk_level`` is coerced to ``"low"`` regardless of dormant reasons.
    * ``parsed_before`` / ``parsed_after`` echo nested ``parsed_proxy_server`` blobs for auditors.

Side effects:
    Pure—no IO.

Audit Notes:
    * Risk labels prioritize operator safety (unexpected localhost proxy enablement ⇒ ``high``) but **do not**
      assert malware—pair with inventories and forensic exports when escalating incidents.

Failure modes:
    * Malformed policy allowlist entries (non-int ports) skip silently during set construction.

Engineering Notes:
    Allowlisted localhost ports downgrade ``high`` to ``medium`` to reduce alert fatigue for sanctioned dev
    ports while preserving visibility.
"""

from __future__ import annotations

from typing import Any


def _norm_str(value: object) -> str:
    """Normalize optional string-like values for safe comparison."""
    if value is None:
        return ""
    return str(value).strip()


def _field_label(key: str) -> str:
    mapping = {
        "proxy_enable": "ProxyEnable",
        "proxy_server": "ProxyServer",
        "auto_config_url": "AutoConfigURL",
        "auto_detect": "AutoDetect",
        "proxy_override": "ProxyOverride",
    }
    return mapping.get(key, key)


def diff_wininet_states(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare immutable state dicts emitted by :func:`~src.proxy_guard.state.snapshot_wininet_state`.

    Args:
        before: Prior snapshot dictionary containing tracked scalar keys and optional ``parsed_proxy_server``.
        after: Current snapshot dictionary with identical structural expectations.
        policy: Optional watch policy influencing remote-proxy severity and localhost port allowance.

    Returns:
        Dict keys:
            ``changed`` (bool), ``changed_fields`` (PascalCase labels), flattened ``before``/``after``,
            qualitative ``risk_level`` (``low`` | ``medium`` | ``high``), explanatory ``reason``,
            structured ``parsed_before`` / ``parsed_after``.

    Side effects:
        None.

    Raises:
        None intentional.

    Decision intent:
        Elevate risk when proxies transition toward loopback listeners or new PAC/remote endpoints; retain
        ``low`` for intentional disables absent simultaneous PAC introductions.

    How to audit:
        Replay consecutive ``snapshot_wininet_state`` outputs through this function offline; exported JSON in
        ``logs/proxy_guard.jsonl`` should match recomputed tuples when timestamps align.

    Recovery guidance:
        High-risk classifications themselves do not mutate settings—operators choose ``proxy-disable``,
        snapshot restore, or policy updates after reviewing attribution output.
    """
    pol = policy or {}
    tracked = ("proxy_enable", "proxy_server", "auto_config_url", "auto_detect", "proxy_override")
    changed_fields: list[str] = []
    flat_before: dict[str, Any] = {}
    flat_after: dict[str, Any] = {}
    changed = False

    for key in tracked:
        b = before.get(key)
        a = after.get(key)
        flat_before[key] = b
        flat_after[key] = a
        if b != a:
            changed = True
            changed_fields.append(_field_label(key))

    parsed_before = before.get("parsed_proxy_server") or {}
    parsed_after = after.get("parsed_proxy_server") or {}

    enabled_before = bool(before.get("is_enabled"))
    enabled_after = bool(after.get("is_enabled"))

    localhost_after = bool(parsed_after.get("is_localhost_proxy"))
    port_after = parsed_after.get("localhost_port")

    pac_before = (str(before.get("auto_config_url") or "").strip() == "")
    pac_after_nonempty = str(after.get("auto_config_url") or "").strip() != ""

    allowed_ports_raw = pol.get("allowed_proxy_ports") or []
    allowed_ports: set[int] = set()
    for x in allowed_ports_raw:
        try:
            allowed_ports.add(int(x))
        except (TypeError, ValueError):
            continue

    risk = "low"
    reasons: list[str] = []

    # Normal disable transitions
    if enabled_before and not enabled_after and not pac_after_nonempty:
        risk = "low"
        reasons.append("Proxy disabled during developer/tool session")

    elif not enabled_before and enabled_after:
        reasons.append("Proxy enabled")
        if localhost_after:
            reasons.append("Enabled target is localhost-loopback proxy")
            risk = "high"

    elif "ProxyServer" in changed_fields:
        reasons.append("ProxyServer registry value mutated")
        if localhost_after:
            reasons.append("New ProxyServer resolves to localhost")
            risk = "high"

    elif "AutoConfigURL" in changed_fields and pac_after_nonempty and pac_before:
        reasons.append("AutoConfigURL added or replaced")
        risk = "medium" if risk != "high" else risk

    elif "AutoConfigURL" in changed_fields:
        reasons.append("AutoConfigURL changed")
        risk = "medium"

    elif changed and risk == "low":
        reasons.append("Proxy-related registry fields changed")

    remote_added = (
        enabled_after
        and not localhost_after
        and _norm_str(after.get("proxy_server")) != ""
        and after.get("proxy_server") is not None
        and (not enabled_before or "ProxyServer" in changed_fields)
    )
    allowed_names = {str(x).lower() for x in (pol.get("allowed_process_names") or []) if isinstance(x, str)}
    if remote_added:
        rs = str(after.get("proxy_server") or "").strip().lower()
        allow_hit = rs and allowed_names and any(name in rs for name in allowed_names)
        if not allow_hit:
            reasons.append("Remote or non-loopback proxy server configured")
            if risk == "low":
                risk = "medium"

    if localhost_after and port_after is not None and int(port_after) in allowed_ports:
        if risk == "high":
            risk = "medium"
        reasons.append("Localhost proxy port explicitly allowlisted")

    if pol.get("deny_unknown_localhost_proxy") and localhost_after:
        reasons.append("Policy flags unknown-loopback-proxy posture as sensitive")

    if not reasons:
        reasons.append("No proxy drift")

    reason = "; ".join(dict.fromkeys(reasons))[:500]

    return {
        "changed": changed,
        "changed_fields": changed_fields,
        "before": flat_before,
        "after": flat_after,
        "risk_level": risk if changed else "low",
        "reason": reason if changed else ("No change" if not changed else reason),
        "parsed_before": parsed_before,
        "parsed_after": parsed_after,
    }

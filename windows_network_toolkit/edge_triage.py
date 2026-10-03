"""One-shot read-only triage for vague "Edge won't load / is slow / blank" reports.

Module responsibility:
    Compose ``why-broken`` (proxy / DNS / IPv6 / optional URL), Edge client state
    (caches, hardware acceleration), risky-extension inventory, and the last live
    blank-screen fix from the audit log into one route plus an ordered fix ladder.
    Each rung carries its exact confirmation token so an operator (or agent) needs a
    single user reply — the token — before any live apply.

System placement:
    CLI: ``edge-triage`` (read-only). Recommends existing gated commands
    (``browser-blank-screen-fix``, ``edge-extensions-disable``,
    ``browser-profile repair-apply``, ``proxy-disable``, ``dns-edge-fix``,
    ``ipv6-prefer-ipv4``); never calls their apply paths.

Key invariants:
    * Read-only: no registry, cache, policy, or process mutation here.
    * Recommendation is not execution authority; tokens are only surfaced.
    * The InPrivate outcome is operator-supplied evidence, never inferred.

Side effects:
    Child-module probes (network, registry reads, Edge User Data reads) and reads of
    ``<audit_dir>/browser-blank-screen.jsonl``, ``edge-extensions-policy.jsonl``, and
    ``browser-diff.jsonl`` (prior site repairs). No audit append.

Failure modes:
    Non-Windows without injected evidence → unsupported. Missing Edge profile →
    extension inventory ``None`` (unknown) and no extension rung.

Audit Notes:
    What could go wrong: stale InPrivate answer steers to the wrong rung.
    Detection: ``fix_options[].when`` states the evidence each rung assumes.
    Recovery: re-run with the correct ``--inprivate``; every rung is reversible or
    cache-only, and ``RESTORE_EDGE_EXTENSIONS_POLICY`` undoes the extension block.
"""

from __future__ import annotations

import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from windows_network_toolkit.audit_store import audit_dir
from windows_network_toolkit.browser_blank_screen import collect_edge_state
from windows_network_toolkit.diagnostics.browser_profile.repair import assert_domain_guard
from windows_network_toolkit.edge_extension_policy import (
    EXTENSION_PRESETS,
    annotate_installed,
    installed_extension_ids,
    read_extension_settings,
)
from windows_network_toolkit.edge_runtime import (
    DEFAULT_SAMPLE_SECONDS,
    analyze_edge_runtime,
    blocked_extension_ids,
    last_live_edge_fix,
    sample_edge_processes,
)
from windows_network_toolkit.safety import CONFIRMATION_TOKENS, DEFAULT_SAFETY_NOTES
from windows_network_toolkit.why_broken import investigate_why_broken

INPRIVATE_CHOICES: tuple[str, ...] = ("unknown", "works", "fails")

CLI = "python -m windows_network_toolkit"
RECENT_FIX_WINDOW_HOURS = 72
_AUDIT_TAIL_LINES = 500
NETWORK_SCORE_THRESHOLD = 0.7

TRIAGE_LIMITATIONS = [
    "Route and ladder are correlation across probes — not proof of a single root cause.",
    "InPrivate outcome is operator-reported; extensions allowed in InPrivate weaken it.",
    "Extension inventory covers the Default Edge profile and a named preset only.",
    *DEFAULT_SAFETY_NOTES,
]

_DIAGNOSIS_BY_CLASSIFICATION = {
    "EDGE_PROFILE_STATE_LIKELY": (
        "Site works in InPrivate, so profile state (extensions or site data) is the likely cause."
    ),
    "EDGE_CACHE_GPU_LIKELY": "Site also fails in InPrivate, so Edge cache/GPU state is likely.",
    "EDGE_CLIENT_STATE_LIKELY": (
        "Network path looks fine; the problem is inside Edge (extensions, site data, or caches)."
    ),
    "EDGE_STATE_EXHAUSTED_ESCALATE": (
        "Edge client fixes are exhausted; the cause is likely site-side or path-specific."
    ),
    "SITE_DATA_FIXED_BEFORE": (
        "A site-data repair was applied to this site before; corrupted site data is the "
        "likely repeat cause."
    ),
}


def _token(name: str) -> str:
    return CONFIRMATION_TOKENS.get(name, name)


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def last_blank_screen_fix(
    audit_root: Path | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Return the most recent *live* blank-screen fix from the audit log.

    Args:
        audit_root: Audit directory (defaults to ``WNT_AUDIT_DIR`` / ``.audit``).
        now: Clock override (tests).

    Returns:
        ``{"timestamp_utc", "age_hours", "recent"}`` or ``None`` when no live
        apply is recorded or the log is unreadable.
    """
    path = (audit_root or audit_dir()) / "browser-blank-screen.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[-_AUDIT_TAIL_LINES:]
    except OSError:
        return None
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        if row.get("event") != "browser_blank_screen_fix":
            continue
        if row.get("dry_run") is not False or row.get("action_allowed") is not True:
            continue
        stamp = str(row.get("timestamp_utc") or "")
        try:
            when = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        except ValueError:
            return {"timestamp_utc": stamp or None, "age_hours": None, "recent": False}
        age = ((now or datetime.now(UTC)) - when).total_seconds() / 3600
        return {
            "timestamp_utc": stamp,
            "age_hours": round(age, 1),
            "recent": age <= RECENT_FIX_WINDOW_HOURS,
        }
    return None


def last_site_repair(audit_root: Path | None, domain: str | None) -> dict[str, Any] | None:
    """Most recent live ``browser-profile repair-apply`` for ``domain`` (or a parent/subdomain).

    Returns:
        ``{"domain", "timestamp_utc", "preview_id"}`` or ``None``.
    """
    if not domain:
        return None
    path = (audit_root or audit_dir()) / "browser-diff.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()[-_AUDIT_TAIL_LINES:]
    except OSError:
        return None
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict) or row.get("event") != "browser_repair_apply":
            continue
        if row.get("decision") != "ALLOW" or row.get("mutated") is not True:
            continue
        repaired = str(row.get("domain") or "")
        if repaired and assert_domain_guard(domain, repaired):
            return {
                "domain": repaired,
                "timestamp_utc": row.get("timestamp_utc"),
                "preview_id": row.get("preview_id"),
            }
    return None


def _network_fix(primary: dict[str, Any]) -> dict[str, Any] | None:
    """Map a strong network hypothesis to its gated fix rung, if one exists."""
    pid = primary.get("id")
    if pid == "proxy":
        token = _token("DISABLE_WININET_PROXY")
        return {
            "id": "disable_wininet_proxy",
            "token": token,
            "preview_command": f"{CLI} proxy-disable --dry-run true",
            "apply_command": f"{CLI} proxy-disable --dry-run false --confirm {token}",
            "changes": "Turns off the HKCU WinINET proxy (ProxyEnable=0).",
            "undo": "Re-enable the proxy in Windows Settings > Network > Proxy.",
            "when": "Proxy points at a dead or suspicious listener.",
        }
    if pid == "dns_edge":
        token = _token("FIX_ERR_NAME_NOT_RESOLVED")
        return {
            "id": "fix_dns_edge",
            "token": token,
            "preview_command": f"{CLI} dns-edge-fix --dry-run true",
            "apply_command": f"{CLI} dns-edge-fix --dry-run false --confirm {token}",
            "changes": "Sets public-DNS-first on the adapter and Edge to use the OS resolver.",
            "undo": "See docs/runbooks/dns-edge-err-name-not-resolved.md (restore section).",
            "when": "Names fail to resolve (ERR_NAME_NOT_RESOLVED).",
        }
    if pid == "ipv6_path" and not primary.get("prefer_ipv4_bit_set"):
        token = _token("PREFER_IPV4_OVER_IPV6")
        return {
            "id": "prefer_ipv4",
            "token": token,
            "preview_command": f"{CLI} ipv6-prefer-ipv4 --dry-run true",
            "apply_command": f"{CLI} ipv6-prefer-ipv4 --dry-run false --confirm {token}",
            "changes": "Sets Tcpip6 DisabledComponents prefer-IPv4 bit (reboot required).",
            "undo": f"{CLI} ipv6-restore-preference (token RESTORE_IPV6_PREFERENCE).",
            "when": "IPv4 works but IPv6 blackholes and prefer-IPv4 is not set yet.",
        }
    return None


def _cache_rung(edge_state: dict[str, Any], recent_fix: dict[str, Any] | None) -> dict[str, Any]:
    token = _token("CLEAR_EDGE_BLANK_SCREEN_CACHES")
    mb = round(int(edge_state.get("cache_bytes_total") or 0) / 1_000_000)
    return {
        "id": "clear_edge_caches",
        "token": token,
        "preview_command": f"{CLI} browser-blank-screen-fix --dry-run true",
        "apply_command": f"{CLI} browser-blank-screen-fix --dry-run false --confirm {token}",
        "changes": (
            f"Closes Edge; deletes GPU/Code/Service Worker caches (~{mb} MB); keeps "
            "hardware acceleration off. Cookies, passwords, and extensions untouched."
        ),
        "undo": "Not needed — Edge rebuilds caches on next browse.",
        "when": "Site also fails in InPrivate (or InPrivate not tested yet).",
        "recently_applied": bool(recent_fix and recent_fix.get("recent")),
        "closes_edge": True,
    }


def _extension_rung(risky_installed: list[dict[str, Any]]) -> dict[str, Any]:
    token = _token("DISABLE_EDGE_EXTENSIONS_VIA_POLICY")
    names = ", ".join(str(r.get("name")) for r in risky_installed)
    return {
        "id": "block_risky_extensions",
        "token": token,
        "preview_command": f"{CLI} edge-extensions-disable --preset cloudflare-risk --dry-run true",
        "apply_command": (
            f"{CLI} edge-extensions-disable --preset cloudflare-risk --dry-run false "
            f"--confirm {token}"
        ),
        "changes": f"Blocks {names} via HKCU Edge ExtensionSettings policy (not uninstalled).",
        "undo": (
            f"{CLI} edge-extensions-restore --dry-run false --confirm "
            f"{_token('RESTORE_EDGE_EXTENSIONS_POLICY')}"
        ),
        "when": "Site works in InPrivate (extensions are off there by default).",
    }


def _site_rung(domain: str | None, previous: dict[str, Any] | None = None) -> dict[str, Any]:
    token = _token("BROWSER_SITE_REPAIR_APPLY")
    target = domain or "<domain>"
    when = "Only this site fails and it works in InPrivate."
    if previous:
        when = (
            f"This repair was applied to {previous['domain']} on {previous['timestamp_utc']}; "
            "the same symptom recurring makes it the first rung."
        )
    return {
        "id": "repair_site_data",
        "token": token,
        "preview_command": f"{CLI} browser-profile repair-preview {target} --browser edge",
        "apply_command": f"{CLI} browser-profile repair-apply <preview_id> --confirm {token}",
        "changes": (
            f"Closes Edge, then clears cookies, site databases, service workers, and site "
            f"permissions for {target} only (you log in there again)."
        ),
        "undo": "Not reversible for that site's data; other sites untouched.",
        "when": when,
        "requires_input": None if domain else "url",
        "previously_applied": previous,
        "closes_edge": True,
    }


def _ladder(
    *,
    inprivate: str,
    cache: dict[str, Any],
    extension: dict[str, Any] | None,
    site: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, str]:
    """Order fix rungs from evidence; return ``(options, recommended, classification)``."""
    recent = bool(cache.get("recently_applied"))
    profile_rungs = [r for r in (extension, site) if r is not None]
    if inprivate != "fails" and site.get("previously_applied") and not site["requires_input"]:
        options = [site, *[r for r in (extension,) if r is not None], cache]
        return options, site, "SITE_DATA_FIXED_BEFORE"
    if inprivate == "works":
        options = [*profile_rungs, cache]
        return options, options[0], "EDGE_PROFILE_STATE_LIKELY"
    if inprivate == "fails":
        if recent:
            return [cache, *profile_rungs], None, "EDGE_STATE_EXHAUSTED_ESCALATE"
        return [cache, *profile_rungs], cache, "EDGE_CACHE_GPU_LIKELY"
    if recent:
        options = [*profile_rungs, cache]
        return options, options[0], "EDGE_CLIENT_STATE_LIKELY"
    return [cache, *profile_rungs], cache, "EDGE_CLIENT_STATE_LIKELY"


def _direct_rung(
    options: list[dict[str, Any]], inprivate: str, recommended: dict[str, Any] | None
) -> dict[str, Any] | None:
    """Rung to offer as a bare token reply (no InPrivate question), if evidence allows.

    Direct when the rung fixed this site before, or when InPrivate is untested but it is
    the only rung not already applied recently (so the question cannot change the answer).
    """
    if recommended is None or recommended.get("requires_input"):
        return None
    if recommended.get("previously_applied"):
        return recommended
    untried = [o for o in options if not o.get("recently_applied")]
    if inprivate == "unknown" and untried == [recommended]:
        return recommended
    return None


def _ask_user(options: list[dict[str, Any]], inprivate: str) -> str | None:
    """Single question that maps each answer to a token (one pause, no follow-ups)."""
    by_id = {o["id"]: o for o in options}
    cache = by_id.get("clear_edge_caches")
    works_rung = by_id.get("block_risky_extensions") or by_id.get("repair_site_data")

    def _reply(rung: dict[str, Any]) -> str:
        extra = " plus the site address" if rung.get("requires_input") == "url" else ""
        return f"reply {rung['token']}{extra}"

    if inprivate == "unknown":
        parts = ["Does the site load in an Edge InPrivate window (Ctrl+Shift+N)?"]
        if works_rung:
            parts.append(f"If YES, {_reply(works_rung)}.")
        if cache and cache.get("recently_applied"):
            parts.append(
                "If NO, Edge caches were already cleared recently — send the failing URL and "
                "whether it loads in another browser (escalation, not another cache clear)."
            )
        elif cache:
            parts.append(f"If NO (or you want the broad fix now), {_reply(cache)}.")
        return " ".join(parts)
    if options:
        return f"To apply the recommended fix, {_reply(options[0])}."
    return None


def triage_edge_loading(
    *,
    url: str | None = None,
    inprivate: str = "unknown",
    why_broken: dict[str, Any] | None = None,
    edge_state: dict[str, Any] | None = None,
    installed_ids: set[str] | None = None,
    audit_root: Path | None = None,
    user_data_dir: Path | None = None,
    now: datetime | None = None,
    runtime_sample: dict[str, Any] | None = None,
    blocked_ids: set[str] | None = None,
    sample_seconds: float = DEFAULT_SAMPLE_SECONDS,
) -> dict[str, Any]:
    """Read-only Edge loading triage with an ordered, token-annotated fix ladder.

    Args:
        url: Failing page (enables URL probes and site-scoped repair rung).
        inprivate: Operator-reported InPrivate outcome: unknown | works | fails.
        why_broken: Injected ``why-broken`` payload (tests); live when None.
        edge_state: Injected ``collect_edge_state`` snapshot (tests).
        installed_ids: Injected installed extension IDs (tests); scanned when None.
        audit_root: Audit dir for last live blank-screen fix lookup.
        user_data_dir: Edge User Data override (tests).
        now: Clock override for recent-fix window (tests).
        runtime_sample: Injected ``sample_edge_processes`` output (tests); sampled live
            only when ``edge_state`` is also live.
        blocked_ids: Injected policy-blocked extension IDs (tests); read from the
            registry only when ``installed_ids`` is also live.
        sample_seconds: CPU sampling window for frozen-tab detection.

    Returns:
        Governance-enveloped payload with ``route``, ``classification``, ``diagnosis``,
        ``detected_issues[]``, ``fix_options[]``, ``recommended_fix``, ``ask_user``, and
        limitations.

    Raises:
        ValueError: If ``inprivate`` is not one of ``INPRIVATE_CHOICES``.
    """
    if inprivate not in INPRIVATE_CHOICES:
        raise ValueError(f"inprivate must be one of {INPRIVATE_CHOICES}, got {inprivate!r}")

    if platform.system() != "Windows" and why_broken is None:
        return attach_governance_envelope(
            {
                "timestamp_utc": _utc_now(),
                "command": "edge-triage",
                "unsupported_platform": True,
                "platform": platform.system(),
                "message": "edge-triage requires Windows (or injected evidence).",
                "limitations": list(TRIAGE_LIMITATIONS),
            }
        )

    why = why_broken if why_broken is not None else investigate_why_broken(url=url)
    primary = why.get("primary_hypothesis") or {}
    domain = (urlparse(url).hostname if url else None) or None

    base: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "command": "edge-triage",
        "url": url,
        "inprivate": inprivate,
        "why_broken": {
            "primary_hypothesis": primary,
            "signals": why.get("signals"),
        },
        "limitations": list(TRIAGE_LIMITATIONS),
    }

    network = (
        _network_fix(primary)
        if float(primary.get("score") or 0) >= NETWORK_SCORE_THRESHOLD
        else None
    )
    if network is not None:
        payload = {
            **base,
            "route": "network",
            "classification": "NETWORK_PATH_LIKELY",
            "fix_options": [network],
            "recommended_fix": network,
            "ask_user": f"Reply with {network['token']} to apply the network fix.",
        }
        payload["operator_next_step"] = _next_step(network)
        return attach_governance_envelope(payload)

    if primary.get("classification") == "URL_BOTH_FAIL":
        payload = {
            **base,
            "route": "unreachable",
            "classification": "SITE_UNREACHABLE",
            "fix_options": [],
            "recommended_fix": None,
            "ask_user": "The site fails on both IPv4 and IPv6 from this PC — is it down for others?",
            "operator_next_step": {
                "kind": "investigate",
                "command": f"{CLI} dns-edge-status",
                "reason": primary.get("summary"),
            },
        }
        return attach_governance_envelope(payload)

    state = edge_state if edge_state is not None else collect_edge_state(user_data_dir)
    installed = (
        installed_ids if installed_ids is not None else installed_extension_ids(user_data_dir)
    )
    if blocked_ids is None:
        blocked_ids = (
            blocked_extension_ids(read_extension_settings()) if installed_ids is None else set()
        )
    preset = [
        {**row, "blocked_by_policy": row["id"] in blocked_ids}
        for row in annotate_installed(EXTENSION_PRESETS["cloudflare-risk"], installed)
    ]
    risky_active = [r for r in preset if r.get("installed") and not r["blocked_by_policy"]]
    recent_fix = last_blank_screen_fix(audit_root, now=now)
    hw = state.get("hardware_acceleration") or {}

    if runtime_sample is None and edge_state is None:
        runtime_sample = sample_edge_processes(sample_seconds)
    runtime = analyze_edge_runtime(
        runtime_sample,
        sample_seconds=sample_seconds,
        last_fix=last_live_edge_fix(audit_root),
        hw_accel_enabled=hw.get("hardware_acceleration_mode_enabled"),
        now=now,
    )
    issues = runtime["issues"]

    cache = _cache_rung(state, recent_fix)
    extension = _extension_rung(risky_active) if risky_active else None
    site_repair = last_site_repair(audit_root, domain)
    options, recommended, classification = _ladder(
        inprivate=inprivate,
        cache=cache,
        extension=extension,
        site=_site_rung(domain, site_repair),
    )

    direct = _direct_rung(options, inprivate, recommended)
    if direct is not None:
        ask = f"Reply {direct['token']} to apply: {direct['changes']}"
    elif recommended is not None:
        ask = _ask_user(options, inprivate)
    else:
        ask = (
            "Edge caches were cleared recently and the site still fails in InPrivate — "
            "likely site-side or path-specific. Which URL fails, and does it load in "
            "another browser?"
        )
    blocking = bool(issues) and (
        issues[0]["severity"] == "high" or issues[0]["id"] == "restart_pending"
    )
    if blocking and direct is not None and direct.get("closes_edge"):
        ask = f"{ask} Closing Edge also clears the detected issue: {issues[0]['summary']}"
    elif blocking:
        ask = f"First: {issues[0]['user_action']} If it still fails: {ask}"

    payload = {
        **base,
        "route": "edge_client",
        "classification": classification,
        "diagnosis": (
            issues[0]["summary"] if issues else _DIAGNOSIS_BY_CLASSIFICATION.get(classification)
        ),
        "detected_issues": issues,
        "manual_steps": [i["user_action"] for i in issues],
        "runtime": {k: v for k, v in runtime.items() if k not in ("issues", "limitations")},
        "edge": {
            "running": state.get("running"),
            "hardware_acceleration_mode_enabled": hw.get("hardware_acceleration_mode_enabled"),
            "hardware_acceleration_source": hw.get("source"),
            "cache_dirs_present": state.get("cache_dirs_present"),
            "cache_bytes_total": state.get("cache_bytes_total"),
        },
        "risky_extensions": preset,
        "recent_blank_screen_fix": recent_fix,
        "previous_site_repair": site_repair,
        "fix_options": options,
        "recommended_fix": recommended,
        "ask_user": ask,
        "ask_kind": "token" if direct is not None else "question",
        "limitations": [*base["limitations"], *runtime["limitations"]],
    }
    payload["operator_next_step"] = (
        _next_step(recommended)
        if recommended is not None
        else {
            "kind": "escalate",
            "command": f"{CLI} why-broken --url <failing-url>",
            "reason": "Edge client remediations exhausted for this symptom window.",
        }
    )
    return attach_governance_envelope(payload)


def _next_step(option: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": f"apply_{option['id']}",
        "command": option["apply_command"],
        "preview_command": option["preview_command"],
        "confirmation_required": option["token"],
        "reason": (
            "Read-only triage complete. Live apply only after the user supplies the exact "
            f"token {option['token']} (same-message apply allowed)."
        ),
    }

"""Browser-profile differential diagnostic runner.

Module responsibility:
    Orchestrate OS baseline, optional HAR import, classification, and
    preview-only repair flows for normal vs private profile differences.

System placement:
    Public CLI entry via package exports (``run_browser_diff``, inspect, site
    state, repair preview/apply stub).

Key invariants:
    Repair apply remains confirmation-gated / preview-oriented.
    Classifications are triage labels, not compromise proof.
    Audit rows may be appended for operator trails.

Side effects:
    May append audit JSONL; may read browser profile files via adapters;
    optional network baseline probes.

Audit Notes:
    Detect unexpected apply attempts via audit + confirmation token gates.
    Re-run with fixtures when live browser DBs are locked.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from windows_network_toolkit.audit_store import append_audit_dict
from windows_network_toolkit.diagnostics.browser_profile.adapters import get_adapter
from windows_network_toolkit.diagnostics.browser_profile.classifier import classify_browser_diff
from windows_network_toolkit.diagnostics.browser_profile.har_compare import compare_hars
from windows_network_toolkit.diagnostics.browser_profile.models import (
    BrowserDiffClassification,
    BrowserDifferentialResult,
)
from windows_network_toolkit.diagnostics.browser_profile.os_baseline import (
    collect_raw_network_baseline,
)
from windows_network_toolkit.diagnostics.browser_profile.repair import (
    build_repair_preview,
    domain_from_url,
)


def _load_har(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _text_report(result: BrowserDifferentialResult) -> str:
    lines = [
        f"Target:\n{result.target_url}",
        "",
        f"Finding:\n{result.classification.value}",
        "",
        f"Confidence:\n{result.confidence:.2f}",
        "",
        "Verified evidence:",
    ]
    for e in result.evidence:
        lines.append(f"* {e}")
    if result.counter_evidence:
        lines.append("")
        lines.append("Counter-evidence:")
        for e in result.counter_evidence:
            lines.append(f"* {e}")
    lines.append("")
    lines.append(f"Epistemic level:\n{result.epistemic_level.value}")
    if result.unverified_assumptions:
        lines.append("")
        lines.append("Not proven / assumptions:")
        for e in result.unverified_assumptions:
            lines.append(f"* {e}")
    if result.recommended_next_steps:
        lines.append("")
        lines.append("Safe next step:")
        for e in result.recommended_next_steps:
            lines.append(f"* {e}")
    lines.append("")
    lines.append("Do not conclude the OS network is universally healthy - only what was tested.")
    return "\n".join(lines)


def run_browser_diff(
    url: str,
    *,
    browser: str = "auto",
    proof: bool = False,
    normal_har: Path | None = None,
    private_har: Path | None = None,
    fixture: Path | dict[str, Any] | None = None,
    run: Callable[..., Any] | None = None,
    inspect_profile: bool = True,
) -> BrowserDifferentialResult:
    """Run the Observation→Hypothesis pipeline for a browser differential diagnosis.

    Collects OS/protocol baseline, optional browser profile metadata, and an
    optional HAR comparison, then classifies the root cause of normal-vs-private
    session discrepancies.

    Args:
        url: Target URL or hostname to diagnose.
        browser: Browser adapter key (``"auto"``, ``"edge"``, ``"chrome"``).
            ``"auto"`` selects Edge if installed, else Chrome.
        proof: When ``True``, attempts a Playwright-based controlled probe instead
            of relying on HAR imports.  Confidence is capped if HARs are absent.
        normal_har: Path to a HAR exported from the user's normal browser profile.
        private_har: Path to a HAR exported from a private/InPrivate session.
        fixture: Path to a JSON fixture file (or a pre-parsed dict) to load instead
            of running live collection.  Used for deterministic testing.
        run: Injectable subprocess callable.  Defaults to ``subprocess.run``.
        inspect_profile: When ``True``, reads local profile metadata, extensions,
            network preferences, and managed policies.

    Returns:
        A ``BrowserDifferentialResult`` with classification, confidence, evidence
        lists, repair preview, audit ID, and a human-readable text report.
    """
    if fixture is not None:
        data = (
            json.loads(Path(fixture).read_text(encoding="utf-8"))
            if isinstance(fixture, Path)
            else fixture
        )
        result = BrowserDifferentialResult.model_validate(data)
        if not result.text_report:
            result.text_report = _text_report(result)
        return result

    adapter = get_adapter(browser)
    browser_name = adapter.name
    audit_id = str(uuid.uuid4())
    target = url if "://" in url else f"https://{url}"
    domain = domain_from_url(target)

    raw = collect_raw_network_baseline(target, run=run)

    profiles = adapter.discover_profiles() if inspect_profile else []
    default = next((p for p in profiles if p.is_default), profiles[0] if profiles else None)
    site_state = None
    extensions: list[Any] = []
    policies: list[Any] = []
    prefs = None
    if default and inspect_profile:
        default = adapter.collect_profile_metadata(default)
        site_state = adapter.collect_site_state_metadata(domain, default)
        extensions = adapter.collect_extension_metadata(default)
        prefs = adapter.collect_network_preferences(default)
        policies = adapter.collect_policy_metadata()

    har_cmp = None
    privacy_redactions: list[str] = []
    normal_session: dict[str, Any] = {}
    private_session: dict[str, Any] = {}
    if normal_har and private_har:
        n_har = _load_har(Path(normal_har))
        p_har = _load_har(Path(private_har))
        har_cmp = compare_hars(n_har, p_har)
        privacy_redactions = list(har_cmp.privacy_redactions)
        normal_session = {
            "source": "har",
            "ok": har_cmp.normal_ok,
            "final_status": har_cmp.normal_final_status,
            "entry_count": har_cmp.normal_entry_count,
        }
        private_session = {
            "source": "har",
            "ok": har_cmp.private_ok,
            "final_status": har_cmp.private_final_status,
            "entry_count": har_cmp.private_entry_count,
        }
    elif proof:
        # Controlled probes optional — clearly labeled
        private_session = adapter.run_controlled_probe(target, "private")
        normal_session = adapter.run_controlled_probe(target, "stateful")
        private_session["label"] = "controlled_reproduction_not_user_profile"
        normal_session["label"] = "controlled_reproduction_not_user_profile"

    classification, confidence, epistemic, evidence, counter, assumptions, next_steps = (
        classify_browser_diff(
            raw=raw,
            har=har_cmp,
            site_state=site_state,
            extensions=extensions,
            network_prefs=prefs,
            policies=policies,
        )
    )

    if (
        proof
        and classification == BrowserDiffClassification.INSUFFICIENT_BROWSER_EVIDENCE
        and not (normal_har and private_har)
    ):
        assumptions.append(
            "--proof requested but HAR imports were not provided; confidence capped."
        )
        confidence = min(confidence, 0.45)

    differences: list[str] = []
    if har_cmp:
        differences.extend(har_cmp.status_mismatches)
        differences.extend(har_cmp.redirect_diffs)
        if har_cmp.cookie_presence_diff:
            differences.append(har_cmp.cookie_presence_diff)

    repair = build_repair_preview(
        domain,
        browser=browser_name,
        has_cookies=bool(site_state and site_state.cookie_count > 0),
        has_service_workers=bool(site_state and site_state.service_worker_count > 0),
        has_cache=bool(site_state and site_state.cache_present),
        proxy_extension_ids=[
            e.extension_id for e in extensions if e.looks_like_proxy and e.enabled
        ][:3],
    )

    limitations = list(raw.limitations)
    limitations.extend(
        [
            "Private-mode success reduces probability of Windows-wide DNS/TCP/TLS/proxy failure but does not prove those layers are universally healthy.",
            "Cookie values, Authorization headers, and browsing history were not collected.",
            "Read-only real-profile inspection is metadata-only; controlled Playwright probes do not mutate the user profile.",
        ]
    )
    if default and default.browser_open:
        limitations.append(
            "Browser appears open — SQLite cookie DB may be locked; copy may be incomplete."
        )

    result = BrowserDifferentialResult(
        target_url=target,
        browser=browser_name,
        profiles_examined=profiles,
        raw_network=raw,
        normal_session=normal_session,
        private_session=private_session,
        site_state=site_state,
        extensions=extensions,
        policies=policies,
        network_preferences=prefs,
        differences=differences,
        classification=classification,
        confidence=confidence,
        epistemic_level=epistemic,
        evidence=evidence,
        counter_evidence=counter,
        unverified_assumptions=assumptions,
        recommended_next_steps=next_steps,
        repair_preview=repair,
        privacy_redactions=privacy_redactions,
        audit_id=audit_id,
        limitations=limitations,
    )
    result.text_report = _text_report(result)

    append_audit_dict(
        {
            "event": "browser_diff_collect",
            "audit_id": audit_id,
            "target_url": target,
            "browser": browser_name,
            "classification": classification.value,
            "confidence": confidence,
            "epistemic_level": epistemic.value,
            "har_imported": bool(normal_har and private_har),
            "privacy_redactions_count": len(privacy_redactions),
        },
        log_name="browser-diff.jsonl",
    )
    return result


def run_browser_profile_inspect(browser: str = "auto") -> dict[str, Any]:
    """Enumerate local browser profiles, policies, and installation metadata.

    Args:
        browser: Browser adapter key (``"auto"``, ``"edge"``, ``"chrome"``).

    Returns:
        A JSON-serializable dict tagged ``wnt.browser_profile_inspect.v1`` with
        keys ``installation``, ``profiles``, ``policies``, and ``limitations``.
        No cookie values or browsing history are included.
    """
    adapter = get_adapter(browser)
    installed = adapter.detect_installation()
    profiles = adapter.discover_profiles()
    policies = adapter.collect_policy_metadata()
    payload = {
        "schema_version": "wnt.browser_profile_inspect.v1",
        "installation": installed,
        "profiles": [p.model_dump(mode="json") for p in profiles],
        "policies": [p.model_dump(mode="json") for p in policies],
        "limitations": [
            "Metadata only — no cookie values or history exported.",
        ],
    }
    append_audit_dict(
        {"event": "browser_profile_inspect", **installed}, log_name="browser-diff.jsonl"
    )
    return payload


def run_browser_site_state(domain: str, browser: str = "auto") -> dict[str, Any]:
    """Read site-state metadata (cookies, SW, cache) for a domain from the default profile.

    Args:
        domain: Target domain or URL.  Normalized to bare hostname internally.
        browser: Browser adapter key (``"auto"``, ``"edge"``, ``"chrome"``).

    Returns:
        A ``BrowserSiteStateEvidence`` serialized to dict, or an error dict with
        ``"error": "missing_browser_profile"`` when no local profile is found.
        Cookie values are never included.
    """
    adapter = get_adapter(browser)
    profiles = adapter.discover_profiles()
    default = next((p for p in profiles if p.is_default), profiles[0] if profiles else None)
    if default is None:
        return {
            "domain": domain,
            "error": "missing_browser_profile",
            "limitations": ["No Chromium user-data profile found for this browser."],
        }
    state = adapter.collect_site_state_metadata(domain_from_url(domain), default)
    append_audit_dict(
        {"event": "browser_site_state", "domain": state.domain, "cookie_count": state.cookie_count},
        log_name="browser-diff.jsonl",
    )
    return state.model_dump(mode="json")


def run_repair_preview(domain: str, browser: str = "auto") -> dict[str, Any]:
    """Generate a site-scoped browser repair preview for the given domain.

    Reads current site-state and extension metadata from the default profile,
    then delegates to ``build_repair_preview`` to produce a dry-run action plan.
    No browser state is modified.

    Args:
        domain: Target domain or URL.
        browser: Browser adapter key (``"auto"``, ``"edge"``, ``"chrome"``).

    Returns:
        A ``BrowserRepairPreview`` serialized to dict with ``dry_run=True``,
        an action list, and a ``limitations`` section.
    """
    adapter = get_adapter(browser)
    profiles = adapter.discover_profiles()
    default = next((p for p in profiles if p.is_default), profiles[0] if profiles else None)
    has_cookies = has_sw = has_cache = False
    proxy_ids: list[str] = []
    if default:
        state = adapter.collect_site_state_metadata(domain_from_url(domain), default)
        has_cookies = state.cookie_count > 0
        has_sw = state.service_worker_count > 0
        has_cache = state.cache_present
        proxy_ids = [
            e.extension_id
            for e in adapter.collect_extension_metadata(default)
            if e.looks_like_proxy
        ][:3]
    preview = build_repair_preview(
        domain_from_url(domain),
        browser=adapter.name,
        has_cookies=has_cookies,
        has_service_workers=has_sw,
        has_cache=has_cache,
        proxy_extension_ids=proxy_ids,
    )
    append_audit_dict(
        {
            "event": "browser_repair_preview",
            "preview_id": preview.preview_id,
            "domain": preview.domain,
        },
        log_name="browser-diff.jsonl",
    )
    return preview.model_dump(mode="json")


def run_repair_apply(preview_id: str, confirm: str) -> dict[str, Any]:
    """Attempt to apply a repair preview — currently a policy-gated stub.

    Verifies that ``confirm`` matches the required token (``BROWSER_SITE_REPAIR_APPLY``).
    Even on a token match, live Chromium database writes are not implemented in this
    release; operators should use the browser's own site-settings UI.

    Args:
        preview_id: The ``preview_id`` returned by ``run_repair_preview``.
        confirm: Typed confirmation token supplied by the operator.

    Returns:
        A dict with ``decision`` (``"BLOCK"``), ``preview_id``, ``reason``,
        ``mutated`` (always ``False`` in this release), and optionally
        ``limitations`` describing why automated apply is not enabled.
    """
    confirmation_phrase = "BROWSER_SITE_REPAIR_APPLY"
    if confirm != confirmation_phrase:
        payload = {
            "decision": "BLOCK",
            "preview_id": preview_id,
            "reason": "confirm_token_mismatch",
            "required": confirmation_phrase,
            "mutated": False,
        }
        append_audit_dict(
            {"event": "browser_repair_apply_blocked", **payload}, log_name="browser-diff.jsonl"
        )
        return payload
    # Intentionally not implementing live Chromium DB writes in this release —
    # keep preview as the operator output; apply stays gated stub with audit.
    payload = {
        "decision": "BLOCK",
        "preview_id": preview_id,
        "reason": "apply_not_implemented_use_browser_ui",
        "mutated": False,
        "limitations": [
            "Automated Chromium DB mutation is not enabled; use Edge/Chrome site settings for domain clear.",
            "Preview remains the supported remediation artifact.",
        ],
    }
    append_audit_dict({"event": "browser_repair_apply", **payload}, log_name="browser-diff.jsonl")
    return payload

"""HAR comparison Mode A — redacted structural differential.

Module responsibility:
    Compare two exported HAR archives (normal browser profile vs private/incognito
    session) to produce a privacy-safe ``HarComparisonEvidence`` record that the
    classifier can consume without exposing cookie values or user data.

System placement:
    Called by ``runner.run_browser_diff`` when ``--import-normal-har`` and
    ``--import-private-har`` paths are supplied.

Key invariants:
    * ``redact_har`` is applied to both inputs before any analysis.
    * Cookie *presence* is recorded as a boolean flag; values are never stored.
    * Anti-bot, auth-loop, and redirect-diff heuristics are structural signal only —
      not proof of intent or data interception.

Side effects:
    * None — pure comparison over in-memory dicts after redaction.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from windows_network_toolkit.diagnostics.browser_profile.models import (
    EvidenceMeta,
    HarComparisonEvidence,
    HarRequestEvidence,
    ReliabilityTier,
)
from windows_network_toolkit.diagnostics.browser_profile.redaction import redact_har


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _headers_list(headers: Any) -> list[dict[str, Any]]:
    if isinstance(headers, list):
        return headers
    if isinstance(headers, dict):
        return [{"name": k, "value": v} for k, v in headers.items()]
    return []


def _header_value(headers: Any, name: str) -> str | None:
    n = name.lower()
    for h in _headers_list(headers):
        if str(h.get("name") or "").lower() == n:
            return str(h.get("value") or "")
    return None


def _entry_to_evidence(entry: dict[str, Any]) -> HarRequestEvidence:
    req = entry.get("request") or {}
    resp = entry.get("response") or {}
    status = int(resp.get("status") or 0)
    err = entry.get("_error") or resp.get("_error")
    blocked = bool(err) or status == 0 and "blocked" in str(err or "").lower()
    if str(entry.get("_blocked_reason") or "").strip():
        blocked = True
    set_cookies = [
        h
        for h in _headers_list(resp.get("headers"))
        if str(h.get("name") or "").lower() == "set-cookie"
    ]
    cookie_present = _header_value(req.get("headers"), "Cookie") is not None
    sw = bool(
        entry.get("_was_served_from_service_worker") or entry.get("_wasServedFromServiceWorker")
    )
    cache = bool(entry.get("_fromCache") or resp.get("fromDiskCache"))
    timing = entry.get("time")
    try:
        timing_ms = float(timing) if timing is not None else None
    except (TypeError, ValueError):
        timing_ms = None
    return HarRequestEvidence(
        url=str(req.get("url") or ""),
        method=str(req.get("method") or "GET"),
        status=status,
        failed=status >= 400 or status == 0 or blocked,
        blocked_by_client=blocked or "blocked_by_client" in str(err or "").lower(),
        redirect_url=str((resp.get("redirectURL") or "") or "") or None,
        cookie_header_present=cookie_present,
        set_cookie_count=len(set_cookies),
        cache_indicated=cache,
        service_worker_indicated=sw,
        timing_ms=timing_ms,
        error_text=str(err) if err else None,
    )


def _document_entries(entries: list[HarRequestEvidence]) -> list[HarRequestEvidence]:
    docs = [
        e
        for e in entries
        if e.method.upper() == "GET" and not e.url.endswith((".js", ".css", ".png", ".ico"))
    ]
    return docs or entries


def compare_hars(
    normal_har: dict[str, Any],
    private_har: dict[str, Any],
) -> HarComparisonEvidence:
    """Produce a privacy-safe structural differential between two HAR archives.

    Both inputs are passed through ``redact_har`` before any analysis; the
    returned evidence record contains no cookie values or request bodies.

    Args:
        normal_har: Raw HAR dict exported from the user's normal browser profile.
        private_har: Raw HAR dict exported from a private / InPrivate session.

    Returns:
        A ``HarComparisonEvidence`` instance summarising status mismatches,
        redirect-chain differences, cookie-header presence flags, anti-bot and
        auth-loop hints, blocked-by-client URLs, and privacy redaction notes.
        The ``meta`` field is set to ``ReliabilityTier.T3_CONTROLLED_REPRO``.
    """
    normal_r, notes_n = redact_har(normal_har)
    private_r, notes_p = redact_har(private_har)
    notes = sorted(set(notes_n + notes_p))

    n_entries = [_entry_to_evidence(e) for e in (normal_r.get("log") or {}).get("entries") or []]
    p_entries = [_entry_to_evidence(e) for e in (private_r.get("log") or {}).get("entries") or []]

    n_docs = _document_entries(n_entries)
    p_docs = _document_entries(p_entries)
    n_final = n_docs[-1] if n_docs else None
    p_final = p_docs[-1] if p_docs else None

    status_mismatches: list[str] = []
    if n_final and p_final and n_final.status != p_final.status:
        status_mismatches.append(f"final_status normal={n_final.status} private={p_final.status}")

    n_redirects = [e.redirect_url for e in n_entries if e.redirect_url]
    p_redirects = [e.redirect_url for e in p_entries if e.redirect_url]
    redirect_diffs: list[str] = []
    if n_redirects != p_redirects:
        redirect_diffs.append(
            f"normal_redirects={len(n_redirects)} private_redirects={len(p_redirects)}"
        )

    blocked_n = [e.url for e in n_entries if e.blocked_by_client][:20]
    blocked_p = [e.url for e in p_entries if e.blocked_by_client][:20]

    set_n = sum(e.set_cookie_count for e in n_entries)
    set_p = sum(e.set_cookie_count for e in p_entries)
    cookie_diff = None
    n_cookie = any(e.cookie_header_present for e in n_entries)
    p_cookie = any(e.cookie_header_present for e in p_entries)
    if n_cookie != p_cookie:
        cookie_diff = f"cookie_header_present normal={n_cookie} private={p_cookie}"

    auth_loop = False
    auth_hits = 0
    for e in n_entries:
        path = urlparse(e.url).path.lower()
        if any(x in path for x in ("/login", "/signin", "/consent", "/oauth", "/sso", "/auth")):
            auth_hits += 1
        if e.status in {301, 302, 303, 307, 308}:
            auth_hits += 1
    stuck_on_redirect = n_final is not None and 300 <= n_final.status < 400
    if auth_hits >= 3 and n_cookie and (n_final is None or n_final.failed or stuck_on_redirect):
        auth_loop = True

    anti_bot = False
    for e in n_entries:
        if e.status in {403, 429, 503} and (p_final is None or not p_final.failed):
            anti_bot = True
        blob = (e.error_text or "") + e.url.lower()
        if any(x in blob for x in ("captcha", "challenge", "cf-challenge", "bot")):
            anti_bot = True

    cors_csp: list[str] = []
    for e in n_entries:
        if e.status == 0 and e.error_text and "cors" in e.error_text.lower():
            cors_csp.append("cors_failure_hint")
        if "csp" in (e.error_text or "").lower():
            cors_csp.append("csp_failure_hint")

    timing_delta = None
    if n_final and p_final and n_final.timing_ms is not None and p_final.timing_ms is not None:
        timing_delta = round(n_final.timing_ms - p_final.timing_ms, 2)

    def _ok(final: HarRequestEvidence | None, entries: list[HarRequestEvidence]) -> bool | None:
        if final is None and not entries:
            return None
        if final is None:
            return False
        # 3xx alone is not "destination reached" for profile-diff purposes
        return not final.failed and 200 <= final.status < 300

    return HarComparisonEvidence(
        normal_entry_count=len(n_entries),
        private_entry_count=len(p_entries),
        status_mismatches=status_mismatches,
        redirect_diffs=redirect_diffs,
        blocked_in_normal=blocked_n,
        blocked_in_private=blocked_p,
        cookie_presence_diff=cookie_diff,
        set_cookie_count_normal=set_n,
        set_cookie_count_private=set_p,
        normal_ok=_ok(n_final, n_entries),
        private_ok=_ok(p_final, p_entries),
        normal_final_status=n_final.status if n_final else None,
        private_final_status=p_final.status if p_final else None,
        auth_challenge_loop_hint=auth_loop,
        anti_bot_hint=anti_bot,
        cors_csp_hints=sorted(set(cors_csp)),
        timing_delta_ms=timing_delta,
        privacy_redactions=notes,
        meta=EvidenceMeta(
            source="har_compare",
            collected_at_utc=_now(),
            collection_method="har_import",
            reliability_tier=ReliabilityTier.T3_CONTROLLED_REPRO,
            redaction_status="fully_redacted" if notes else "partial",
        ),
    )

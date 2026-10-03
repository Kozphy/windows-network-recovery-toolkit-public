"""Repair preview — never apply without explicit confirm.

Module responsibility:
    Build site-scoped browser cleanup action lists as a dry-run ``BrowserRepairPreview``
    artifact.  No browser state (cookies, storage, extensions) is modified here.

System placement:
    Called by ``runner.run_repair_preview`` and ``runner.run_browser_diff``.
    Apply path lives in ``runner.run_repair_apply`` (confirmation-gated site-scoped mutations).

Key invariants:
    * ``build_repair_preview`` always sets ``dry_run=True``.
    * Domain-guard helper prevents unrelated-domain actions from being included.
    * Apply requires the typed token ``BROWSER_SITE_REPAIR_APPLY`` — not enforced here.

Side effects:
    * None — pure preview data construction.
"""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

from windows_network_toolkit.diagnostics.browser_profile.adapters.chromium import domain_matches
from windows_network_toolkit.diagnostics.browser_profile.models import BrowserRepairPreview


def domain_from_url(url: str) -> str:
    """Extract the lowercase hostname from a URL or bare domain string.

    Args:
        url: Full URL (e.g. ``"https://example.com/path"``) or bare hostname.

    Returns:
        Lowercase hostname suitable for use as a domain guard key.
    """
    host = urlparse(url if "://" in url else f"https://{url}").hostname or url
    return host.lower()


def build_repair_preview(
    domain: str,
    *,
    browser: str,
    has_cookies: bool = False,
    has_service_workers: bool = False,
    has_cache: bool = False,
    proxy_extension_ids: list[str] | None = None,
) -> BrowserRepairPreview:
    """Build a site-scoped browser cleanup plan as a preview-only artifact.

    Generates a ``BrowserRepairPreview`` listing the actions that *would* be
    taken if the operator confirms with ``BROWSER_SITE_REPAIR_APPLY``.  No
    browser state is mutated by this function.

    Args:
        domain: Target domain (or URL — normalized via ``domain_from_url`` inside
            the function).  Domain guard restricts all actions to this domain only.
        browser: Browser adapter name (e.g. ``"edge"``, ``"chrome"``).
        has_cookies: Whether domain cookies were found in the profile; gates the
            ``delete_domain_cookies`` action's ``applies_if`` flag.
        has_service_workers: Whether domain service workers were detected; gates the
            ``unregister_domain_service_workers`` action.
        has_cache: Whether HTTP cache entries are present for the domain.
        proxy_extension_ids: Up to 3 extension IDs flagged as proxy-capable; each
            adds a ``disable_extension_<id>`` preview action.

    Returns:
        A ``BrowserRepairPreview`` with ``dry_run=True``, a stable
        ``preview_id``, an ``actions`` list, and a ``limitations`` list
        clarifying that no browser state was modified.
    """
    d = domain.lower().lstrip(".")
    actions: list[dict[str, Any]] = [
        {
            "id": "delete_domain_cookies",
            "description": f"Delete cookies scoped to {d} only",
            "destructive": True,
            "applies_if": has_cookies,
            "domain_guard": d,
        },
        {
            "id": "delete_domain_cache",
            "description": f"Delete HTTP cache entries associated with {d}",
            "destructive": True,
            "applies_if": has_cache,
        },
        {
            "id": "delete_domain_local_storage",
            "description": f"Delete Local Storage / IndexedDB for {d}",
            "destructive": True,
        },
        {
            "id": "unregister_domain_service_workers",
            "description": f"Unregister service workers for {d}",
            "destructive": True,
            "applies_if": has_service_workers,
        },
        {
            "id": "reset_domain_permissions",
            "description": f"Reset site permissions for {d}",
            "destructive": True,
        },
        {
            "id": "create_clean_test_profile",
            "description": "Create a dedicated toolkit test profile (does not wipe user Default)",
            "destructive": False,
        },
        {
            "id": "reset_secure_dns_to_system",
            "description": "Reset Secure DNS mode to system default in test profile",
            "destructive": False,
        },
    ]
    for ext_id in proxy_extension_ids or []:
        actions.append(
            {
                "id": f"disable_extension_{ext_id}",
                "description": f"Disable extension {ext_id} for testing only",
                "destructive": True,
            }
        )

    return BrowserRepairPreview(
        preview_id=f"brp-{uuid.uuid4().hex[:12]}",
        domain=d,
        browser=browser,
        dry_run=True,
        actions=actions,
        backup_plan="Export non-secret BrowserSiteStateEvidence JSON before apply.",
        requires_confirm_token="BROWSER_SITE_REPAIR_APPLY",
        limitations=[
            "Preview only — no cookies, storage, or extensions were modified.",
            "Never reset the whole browser profile when site-scoped cleanup suffices.",
            f"Domain guard uses matching helper; unrelated domains must not match '{d}'.",
            "Apply requires: wnrt browser-profile repair-apply <preview-id> --confirm BROWSER_SITE_REPAIR_APPLY",
        ],
    )


def assert_domain_guard(target_domain: str, candidate_domain: str) -> bool:
    """Verify that a repair action domain matches the target domain.

    Used by tests to ensure site-scoped repair actions cannot accidentally
    affect an unrelated domain.  Matching is bidirectional: either domain may
    be a suffix-subdomain of the other.

    Args:
        target_domain: The domain the repair was triggered for.
        candidate_domain: The domain of a proposed repair action.

    Returns:
        ``True`` if the candidate domain is within the same suffix scope as the
        target domain (i.e. one is a subdomain of the other); ``False`` otherwise.
    """
    return domain_matches(candidate_domain, target_domain) or domain_matches(
        target_domain, candidate_domain
    )

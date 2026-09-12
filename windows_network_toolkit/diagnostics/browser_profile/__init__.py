"""Browser-profile differential diagnostics package.

Module responsibility:
    Observation → Hypothesis → Proof pipeline for normal vs private browser-profile
    site behavior differences (cookies/policies/HAR structure — not malware verdicts).

System placement:
    CLI browser-profile commands via ``runner`` public exports.

Key invariants:
    Cookie values, Authorization headers, and browsing history are never collected.
    Repair is preview-only; apply requires a typed confirmation token.
    Classifications are triage labels — not security verdicts or compromise proof.

Typical workflow:
    1. ``run_browser_diff`` — OS/protocol baseline + optional HAR import + classify.
    2. ``run_browser_profile_inspect`` — enumerate local profiles and managed policies.
    3. ``run_browser_site_state`` — cookie/SW/cache metadata for a domain.
    4. ``run_repair_preview`` — site-scoped cleanup plan (dry-run).
    5. ``run_repair_apply`` — confirmation-gated apply stub (currently preview-only).
"""

from windows_network_toolkit.diagnostics.browser_profile.runner import (
    run_browser_diff,
    run_browser_profile_inspect,
    run_browser_site_state,
    run_repair_apply,
    run_repair_preview,
)

__all__ = [
    "run_browser_diff",
    "run_browser_profile_inspect",
    "run_browser_site_state",
    "run_repair_apply",
    "run_repair_preview",
]

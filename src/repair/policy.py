"""Recommendation tier literals and textual guardrails for repair previews."""

from __future__ import annotations

SAFE_TIER = "safe"
GUIDED_TIER = "guided"
ADVANCED_TIER = "advanced"


def tier_safe() -> str:
    """Return ``SAFE_TIER`` token for CLI JSON consumers."""
    return SAFE_TIER


def assert_no_firewall_reset_in_preview(text_blob: str) -> None:
    """Guardrail tests / runtime sanity: ensure previews never silently add firewall resets."""
    lower = text_blob.lower()
    if "reset_firewall" in lower or ("advfirewall" in lower and "reset" in lower):
        raise ValueError("Policy violation: firewall reset must never be auto-linked to proxy remediation.")

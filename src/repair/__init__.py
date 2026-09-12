"""Repair preview/apply primitives limited to audited WinINET HKCU proxy disables.

Audit Notes:
    Successful applies append JSONL outcomes via CLI handlers—not this package alone.
"""

from .policy import assert_no_firewall_reset_in_preview, tier_safe
from .preview import summarize_mutations_plaintext

__all__ = ["assert_no_firewall_reset_in_preview", "summarize_mutations_plaintext", "tier_safe"]

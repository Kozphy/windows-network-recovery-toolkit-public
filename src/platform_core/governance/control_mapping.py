"""SOC2 / ITGC-style control mapping (informational, not certification)."""

from __future__ import annotations

from typing import Literal

ControlCategory = Literal["Prevent", "Detect", "Respond", "Approve", "Recover", "Audit"]

_MAPPING: dict[str, list[ControlCategory]] = {
    "ALLOW": ["Prevent", "Audit"],
    "PREVIEW_ONLY": ["Detect", "Audit"],
    "REQUIRE_HUMAN_APPROVAL": ["Approve", "Prevent", "Audit"],
    "BLOCK": ["Prevent", "Detect", "Audit"],
    "ROLLBACK_REQUIRED": ["Recover", "Audit"],
}


def map_policy_outcome_to_controls(outcome: str) -> list[ControlCategory]:
    """Map policy outcome to controls.

    Args:
        outcome: outcome supplied by the caller.

    Returns:
        The computed `list[ControlCategory]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return list(_MAPPING.get(outcome, ["Audit"]))

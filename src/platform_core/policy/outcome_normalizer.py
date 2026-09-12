"""Normalize legacy/YAML policy outcomes to canonical gate vocabulary.

Module responsibility:
    Maps the large set of legacy, YAML-defined, and human-readable policy outcome
    strings (e.g. ``"ALLOW_OBSERVE"``, ``"BLOCK_DESTRUCTIVE"``,
    ``"REQUIRE_TYPED_CONFIRMATION"``) to the six canonical ``CanonicalPolicyGate``
    values used internally by the policy engine.  Unrecognised strings default to
    ``PREVIEW`` as the most restrictive safe fallback.

System placement:
    Called by the policy engine before evaluating any action gate.  The
    ``_LEGACY_MAP`` dict is constructed at import time and is read-only at runtime.

Key invariants:
    - Unknown outcome strings are silently coerced to ``PREVIEW`` rather than
      raising, ensuring misconfigured YAML policies default to the safest
      non-blocking outcome.
    - Empty or blank strings also return ``PREVIEW``.
    - The canonical gate set (``CanonicalPolicyGate``) is smaller than the legacy
      input vocabulary; many-to-one mappings are intentional and documented in
      ``_LEGACY_MAP``.

Side effects:
    None.

Failure modes:
    If a caller passes a genuinely new outcome string not present in
    ``_LEGACY_MAP``, it silently receives ``PREVIEW``; no warning is emitted.
    Operators adding new outcome types must register them in ``_LEGACY_MAP``
    explicitly.
"""

from __future__ import annotations

from enum import StrEnum


class CanonicalPolicyGate(StrEnum):
    """Represent the canonical policy gate enum.

    Variants:
        ALLOW: Structured value carried by this enum.
        PREVIEW: Structured value carried by this enum.
        BLOCK: Structured value carried by this enum.
        REQUIRE_CONFIRMATION: Structured value carried by this enum.
        REQUIRE_ADMIN: Structured value carried by this enum.
        REQUIRE_HUMAN_REVIEW: Structured value carried by this enum.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    ALLOW = "ALLOW"
    PREVIEW = "PREVIEW"
    BLOCK = "BLOCK"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"
    REQUIRE_ADMIN = "REQUIRE_ADMIN"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"


_LEGACY_MAP: dict[str, CanonicalPolicyGate] = {
    "ALLOW": CanonicalPolicyGate.ALLOW,
    "ALLOW_OBSERVE": CanonicalPolicyGate.ALLOW,
    "ALLOW_PREVIEW": CanonicalPolicyGate.PREVIEW,
    "PREVIEW": CanonicalPolicyGate.PREVIEW,
    "PREVIEW_ONLY": CanonicalPolicyGate.PREVIEW,
    "OBSERVE": CanonicalPolicyGate.ALLOW,
    "BLOCK": CanonicalPolicyGate.BLOCK,
    "BLOCK_DESTRUCTIVE": CanonicalPolicyGate.BLOCK,
    "BLOCK_RECOMMENDED": CanonicalPolicyGate.BLOCK,
    "BLOCK_UNSAFE_ACTION": CanonicalPolicyGate.BLOCK,
    "BLOCK_AUTOMATION": CanonicalPolicyGate.BLOCK,
    "BLOCK_LOW_CONFIDENCE": CanonicalPolicyGate.BLOCK,
    "REQUIRE_TYPED_CONFIRMATION": CanonicalPolicyGate.REQUIRE_CONFIRMATION,
    "REQUIRE_CONFIRMATION": CanonicalPolicyGate.REQUIRE_CONFIRMATION,
    "REQUIRE_ADMIN": CanonicalPolicyGate.REQUIRE_ADMIN,
    "REQUIRE_HUMAN_APPROVAL": CanonicalPolicyGate.REQUIRE_HUMAN_REVIEW,
    "REQUIRE_HUMAN_REVIEW": CanonicalPolicyGate.REQUIRE_HUMAN_REVIEW,
    "HUMAN_REVIEW_REQUIRED": CanonicalPolicyGate.REQUIRE_HUMAN_REVIEW,
    "ESCALATE_REVIEW": CanonicalPolicyGate.REQUIRE_HUMAN_REVIEW,
    "CORRELATION_ONLY_ALERT": CanonicalPolicyGate.PREVIEW,
    "ROLLBACK_REQUIRED": CanonicalPolicyGate.REQUIRE_HUMAN_REVIEW,
}


def normalize_policy_outcome(outcome: str) -> CanonicalPolicyGate:
    """Normalize policy outcome.

    Args:
        outcome: outcome supplied by the caller.

    Returns:
        The computed `CanonicalPolicyGate` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    key = str(outcome or "").strip().upper()
    if not key:
        return CanonicalPolicyGate.PREVIEW
    return _LEGACY_MAP.get(key, CanonicalPolicyGate.PREVIEW)

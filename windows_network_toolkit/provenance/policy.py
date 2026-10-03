"""Policy gate for domain provenance — human review only, no remediation.

Module responsibility:
    Convert a provenance score into a governance policy decision that always
    requires human review and never authorizes attribution enforcement or
    remediation apply based on country hypotheses.

System placement:
    After scoring; before audit append / CLI emit.

Key invariants:
    * ``decision`` is always ``ALLOW_WITH_HUMAN_REVIEW`` for assessments.
    * ``attribution_enforcement_allowed`` is always False.
    * ``remediation_allowed`` is always False.
    * Blocked action ids are listed explicitly for safety contracts.

Side effects:
    None.
"""

from __future__ import annotations

from windows_network_toolkit.provenance.models import (
    PolicyDecision,
    ProvenancePolicy,
    ProvenanceScore,
)
from windows_network_toolkit.safety import DEFAULT_SAFETY_NOTES

PROVENANCE_BLOCKED_ACTIONS = (
    "ATTRIBUTION_ENFORCEMENT",
    "PROVENANCE_BASED_REMEDIATION",
    "AUTO_BLOCK_BY_OPERATOR_COUNTRY",
    "AUTO_BLOCK_BY_INFRASTRUCTURE_COUNTRY",
)


def evaluate_provenance_policy(score: ProvenanceScore) -> ProvenancePolicy:
    """Build the mandatory human-review policy envelope.

    Args:
        score: Scored provenance result (used only for notes).

    Returns:
        ``ProvenancePolicy`` that blocks enforcement and remediation.
    """
    notes = [
        "Provenance assessment is read-only management information.",
        "Human review is required before any operational decision.",
        "Operator-country hypotheses must not trigger automated enforcement.",
        "Infrastructure mismatch is informational only.",
    ]
    if score.mismatches:
        notes.append(
            "Informational infrastructure mismatch present — do not treat hosting "
            "country as operator country."
        )
    if not score.operator_country:
        notes.append("Insufficient operator signals — do not invent a country.")
    notes.extend(DEFAULT_SAFETY_NOTES[:2])

    return ProvenancePolicy(
        decision=PolicyDecision.ALLOW_WITH_HUMAN_REVIEW,
        human_review_required=True,
        attribution_enforcement_allowed=False,
        remediation_allowed=False,
        blocked_actions=list(PROVENANCE_BLOCKED_ACTIONS),
        notes=notes,
    )


def is_provenance_action_blocked(action: str) -> bool:
    """Return True when an action id is blocked for provenance misuse."""
    return action.upper() in PROVENANCE_BLOCKED_ACTIONS

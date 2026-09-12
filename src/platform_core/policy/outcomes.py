"""Policy outcome vocabulary — canonical gate name literals.

Module responsibility:
    Defines ``PolicyOutcomeName`` as a ``Literal`` type alias enumerating the five
    valid top-level policy gate values: ``ALLOW``, ``PREVIEW_ONLY``,
    ``REQUIRE_HUMAN_APPROVAL``, ``BLOCK``, and ``ROLLBACK_REQUIRED``.  This type
    is used in function signatures and Pydantic models to constrain outcome fields
    without depending on the full ``CanonicalPolicyGate`` enum.

System placement:
    Imported by the policy engine, the decision engine, and API response models.
    ``outcome_normalizer.py`` maps legacy/YAML strings onto the broader
    ``CanonicalPolicyGate`` enum; this module provides the user-facing subset.

Key invariants:
    ``PolicyOutcomeName`` is a ``Literal`` — static checkers enforce exhaustive
    handling at call sites.  Adding a new gate requires updating both this literal
    and ``CanonicalPolicyGate`` in ``outcome_normalizer.py``.
"""

from __future__ import annotations

from typing import Literal

PolicyOutcomeName = Literal[
    "ALLOW",
    "PREVIEW_ONLY",
    "REQUIRE_HUMAN_APPROVAL",
    "BLOCK",
    "ROLLBACK_REQUIRED",
]

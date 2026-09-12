"""Policy sub-package — evaluation, outcomes, and normalisation.

Module responsibility:
    Re-exports the two primary public symbols used by callers that import from
    ``src.platform_core.policy``: the ``evaluate_policy`` function (from
    ``engine.py``) and the ``PolicyOutcomeName`` literal type (from
    ``outcomes.py``).

System placement:
    Consumed by the ``diagnose``, ``proxy-disable``, and ``proxy-watch`` CLI
    commands, by API route handlers, and by the decision engine when translating
    classification results into gated policy decisions.
"""

from .engine import evaluate_policy
from .outcomes import PolicyOutcomeName

__all__ = ["PolicyOutcomeName", "evaluate_policy"]

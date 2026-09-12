"""Decision engine: hypothesis ranking, risk classification, policy, and remediation planning.

Module responsibility:
    Public surface of the ``decision`` sub-package.  Exports the typed result
    model, incident-type enumeration, policy evaluation, and the two primary
    entry points: ``evaluate_incident`` (produces a ``DecisionResult`` from
    signals) and ``plan_remediation`` (produces dry-run previews from a
    ``DecisionResult``).

System placement:
    Sits between the ``evidence`` layer (signals/bundle) and the ``platform``
    API/pipeline layer.  Imports from ``proxy_reasoning`` (deterministic
    scenario ranking) and ``windows_network_toolkit.safety`` (policy gates).

Key invariants:
    * All remediation actions are preview-only by default (``dry_run=True``).
    * ``requires_confirmation=True`` on any decision that could mutate system
      state; callers must obtain an explicit typed token before executing.
    * Incident classification is a hypothesis, not a verdict:
      classification ≠ accusation.
"""

from .decision_model import DecisionResult, IncidentType
from .hypothesis_engine import evaluate_incident
from .policy_engine import PolicyOutcome, evaluate_policy
from .remediation_planner import plan_remediation

__all__ = [
    "DecisionResult",
    "IncidentType",
    "PolicyOutcome",
    "evaluate_incident",
    "evaluate_policy",
    "plan_remediation",
]

"""Policy decision engine: combine classification, proof, and action into a PolicyDecision.

Module responsibility:
    Orchestrate the legacy (pre-ERP) policy decision path: live-classify or
    accept a supplied ``ClassificationResult``, optionally run proof checks,
    evaluate policy gates, and compute a risk score — returning all four
    artefacts in a single response dict.

System placement:
    Used by operator CLI commands and integration tests that exercise the
    pre-ERP decision path.  The newer ERP pipeline (``pipeline.py``) uses
    ``hypothesis_engine.evaluate_incident`` and
    ``platform.policy.evaluate_policy`` directly.

Key invariants:
    * ``dry_run=True`` is the default; ``decide()`` never mutates system state
      regardless of the ``dry_run`` value — mutation is the responsibility of
      the remediation executor, which is a separate path.
    * When neither ``classification`` nor ``proof`` is supplied, live
      collection is performed via ``classify_from_live`` and
      ``run_diagnose_proof``; these may read from registry or network.

Side effects:
    May invoke ``classify_from_live`` (reads Windows registry/network state)
    and ``run_diagnose_proof`` (reads proxy reasoning signals) when their
    respective arguments are omitted.

Failure modes:
    Exceptions from live collection propagate to the caller without wrapping.
"""

from __future__ import annotations

from typing import Any

from windows_network_toolkit.models import ClassificationResult, ProofResult
from windows_network_toolkit.platform.policy import evaluate_policy
from windows_network_toolkit.platform.risk_scoring import score_risk
from windows_network_toolkit.proof import run_diagnose_proof
from windows_network_toolkit.proxy_classification import classify_from_live


def decide(
    action: str,
    *,
    classification: ClassificationResult | None = None,
    proof: ProofResult | None = None,
    dry_run: bool = True,
    confirmation: str = "",
    **kwargs: Any,
) -> dict[str, Any]:
    """Evaluate a policy decision for the given action and classification context.

    Performs live classification and proof steps when the corresponding
    arguments are omitted.  Always runs policy evaluation and risk scoring.

    Args:
        action: The action token to evaluate (e.g. ``"DISABLE_WININET_PROXY"``).
        classification: Pre-computed ``ClassificationResult``; when ``None``,
            ``classify_from_live(**kwargs)`` is called.
        proof: Pre-computed ``ProofResult``; when ``None``,
            ``run_diagnose_proof(**kwargs)`` is called.
        dry_run: Passed through to ``evaluate_policy``; does not affect the
            classification or proof steps.
        confirmation: Typed confirmation phrase; matched against the expected
            token in ``evaluate_policy``.
        **kwargs: Forwarded to ``classify_from_live`` and ``run_diagnose_proof``
            when those are invoked implicitly.

    Returns:
        Dict with keys ``"policy_decision"``, ``"classification"``,
        ``"proof"``, and ``"risk_assessment"``.
    """
    cls = classification or classify_from_live(**kwargs)
    pr = proof or run_diagnose_proof(**kwargs)
    decision = evaluate_policy(action, cls, pr, dry_run=dry_run, confirmation=confirmation)
    risk = score_risk(cls, pr)
    return {
        "policy_decision": decision.to_dict(),
        "classification": cls.to_dict(),
        "proof": pr.to_dict(),
        "risk_assessment": risk,
    }

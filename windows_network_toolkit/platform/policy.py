"""Policy evaluation facade for the Technology Risk platform.

Module responsibility:
    Enforce action-level policy gates before any remediation step is permitted.
    Consults ``windows_network_toolkit.safety`` for blocked actions and
    confirmation tokens, then applies classification-aware allow/deny logic for
    each supported action type.

System placement:
    Called by ``platform.decision_engine.decide`` and directly by the ERP
    pipeline.  Also imported in integration tests for the policy safety
    contract.  Sits in front of all remediation executors.

Key invariants:
    * Any action in ``safety.BLOCKED_ACTIONS`` (e.g. ``"KILL_PROXY_PROCESS"``)
      is denied unconditionally — no classification context can override a
      safety block.
    * ``DISABLE_WININET_PROXY`` is allowed only when:
      (a) the classification is ``DEAD_PROXY_CONFIG`` or
          ``WININET_WINHTTP_MISMATCH``, AND
      (b) ``dry_run=False``, AND
      (c) the caller supplies the exact ``CONFIRMATION_TOKEN``.
    * The default deny-all fallback (``"Unknown action — default deny"``)
      ensures that new action tokens are blocked until explicitly policy-
      approved.

Side effects:
    None — pure evaluation; no registry, network, or file I/O.

Failure modes:
    None expected from this module; exceptions in ``safety_checks_for``
    would propagate to the caller.

Audit Notes:
    Every ``PolicyDecision`` carries ``safety_checks`` from
    ``safety.safety_checks_for``; audit records should log the full
    ``PolicyDecision.to_dict()`` so that the rationale is traceable.
"""

from __future__ import annotations

from windows_network_toolkit.models import ClassificationResult, PolicyDecision, ProofResult
from windows_network_toolkit.safety import CONFIRMATION_TOKENS, is_blocked_action, safety_checks_for


def evaluate_policy(
    action: str,
    classification: ClassificationResult,
    proof: ProofResult | None = None,
    *,
    dry_run: bool = True,
    confirmation: str = "",
) -> PolicyDecision:
    """Evaluate an action request against safety policy and classification context.

    Applies the following precedence rules:

    1. Actions in ``BLOCKED_ACTIONS`` → unconditional deny.
    2. ``DISABLE_WININET_PROXY`` → allowed only for specific classifications
       with explicit confirmation; denied for all others.
    3. ``KILL_PROXY_PROCESS`` → unconditional deny (no silent process killing).
    4. Any unrecognised action → default deny.

    Args:
        action: Action token to evaluate (case-insensitive; normalised to
            upper-case internally).
        classification: Current ``ClassificationResult`` from the classifier.
        proof: Optional ``ProofResult``; currently unused in gate logic but
            included for future extension.
        dry_run: When ``True`` (default), the ``allowed`` flag in the returned
            ``PolicyDecision`` is ``False`` even for qualifying actions — live
            execution requires ``dry_run=False`` plus the correct token.
        confirmation: Typed confirmation phrase from the operator; matched
            against the expected ``CONFIRMATION_TOKEN`` for the action.

    Returns:
        A ``PolicyDecision`` with ``allowed``, ``requires_confirmation``,
        ``confirmation_token``, ``risk_level``, ``rationale``, and
        ``safety_checks``.
    """
    action_upper = action.upper()

    if is_blocked_action(action_upper):
        return PolicyDecision(
            action=action_upper,
            allowed=False,
            requires_confirmation=True,
            confirmation_token="",
            risk_level="high",
            rationale=f"Action {action_upper} is blocked by safety policy.",
            safety_checks=safety_checks_for(action_upper),
        )

    token = CONFIRMATION_TOKENS.get(action_upper, action_upper)
    primary = classification.primary_classification

    if action_upper == "DISABLE_WININET_PROXY":
        if primary in {"DEAD_PROXY_CONFIG", "WININET_WINHTTP_MISMATCH"}:
            allowed = not dry_run and confirmation == token
            return PolicyDecision(
                action=action_upper,
                allowed=allowed,
                requires_confirmation=True,
                confirmation_token=token,
                risk_level="medium",
                rationale="Dead or mismatched localhost proxy can be disabled only with user confirmation.",
                safety_checks=safety_checks_for(action_upper),
            )
        return PolicyDecision(
            action=action_upper,
            allowed=False,
            requires_confirmation=True,
            confirmation_token=token,
            risk_level="medium",
            rationale=f"Classification {primary} does not meet safe-disable criteria without review.",
            safety_checks=safety_checks_for(action_upper),
        )

    if action_upper == "KILL_PROXY_PROCESS":
        return PolicyDecision(
            action=action_upper,
            allowed=False,
            requires_confirmation=True,
            confirmation_token="",
            risk_level="high",
            rationale="No silent process killing — action unsupported.",
            safety_checks=safety_checks_for(action_upper),
        )

    return PolicyDecision(
        action=action_upper,
        allowed=False,
        requires_confirmation=True,
        confirmation_token=token,
        risk_level="low",
        rationale="Unknown action — default deny.",
        safety_checks=safety_checks_for(action_upper),
    )

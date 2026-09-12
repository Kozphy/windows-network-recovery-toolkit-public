"""Deterministic event/state reasoning engine for endpoint reliability.

Module responsibility:
    Orchestrate the deterministic Observation → Event → State Transition → Hypothesis →
    Reliability Impact → Policy chain. Produces a :class:`~platform_core.reasoning_models.ReasoningRun`
    with embedded evidence tree and policy decision. Never mutates Windows state and never
    spawns subprocesses; this module operates purely on caller-provided observations.

System placement:
    Used by ``platform_core.product_contract`` (diagnosis) and the ``platform_core.agent_planner``
    indirectly through stored diagnoses. Replay paths in :mod:`platform_core.reasoning_audit`
    feed observations back into :func:`run_reasoning` to recompute decisions without re-probing
    the host.

Key invariants:
    * The function set is **pure** with respect to the input ``Observation`` list. Same
      observations + same proof_result + same requested_action always produce the same
      :class:`PolicyDecision` outcome and reason codes.
    * ``DESTRUCTIVE_ACTION_TOKENS`` substring matches always BLOCK regardless of confidence
      or proof status.
    * Only action keys in :data:`SAFE_REGISTRY_ACTIONS` may ever reach an ``ALLOW`` outcome,
      and only with ``CONFIRMED`` proof + explicit confirmation + no conflicting signals.
    * High/critical impact without ``CONFIRMED`` proof is forced to ``PREVIEW`` even if the
      ALLOW gate above is widened in the future (see :func:`evaluate_reasoning_policy`).

Input assumptions:
    Caller supplies a list of :class:`Observation` rows. Signal names and value semantics
    must match those used by ``platform_core.failure_scenarios.normalize_signals``; unknown
    signal names are tolerated (ignored) but contribute nothing to scoring.

Output guarantees:
    :func:`run_reasoning` returns a :class:`ReasoningRun` that is JSON-serializable via the
    Pydantic/dataclass surfaces in ``reasoning_models``. ``confidence`` is an ordinal score
    in ``[0.0, 0.98]``, never a calibrated probability.

Side effects:
    None. Persistence and audit row writes are caller responsibilities.

Audit Notes:
    The reasoning engine is the **single authoritative policy gate** for the endpoint
    reliability platform. When operators dispute a decision:

    * Capture the input ``observations`` list and ``proof_result`` from the audit row.
    * Re-run :func:`run_reasoning` with the same arguments — output must match byte-for-byte
      because the engine is deterministic.
    * If outputs diverge, suspect a code change to scoring weights, scenario definitions, or
      policy thresholds; review git history for ``platform_core/reasoning_engine.py``,
      ``platform_core/failure_scenarios.py``, and ``platform_core/impact_score.py``.

Engineering Notes:
    The module deliberately avoids any I/O or subprocess to keep it replayable from JSONL
    and easy to test offline. Heuristic confidence is **rule-derived ordinal weight**, not a
    probability; widening it to a calibrated estimator would require fixture-driven
    calibration plus a documented contract change in ``platform_core.reasoning_models``.
"""

from __future__ import annotations

from typing import Any

from platform_core import policy_v2 as pv2
from platform_core.evidence_tree import build_evidence_tree
from platform_core.failure_scenarios import (
    default_failure_scenarios,
    detect_endpoint_events,
    event_types,
    normalize_signals,
)
from platform_core.impact_score import calculate_reliability_impact
from platform_core.reasoning_models import (
    EndpointEvent,
    EvidenceTree,
    Observation,
    PolicyDecision,
    ProofResult,
    ReasoningRun,
    StateTransition,
    new_id,
)
from platform_core.state_machine import canonical_state_path, infer_canonical_transitions

SAFE_REGISTRY_ACTIONS = {
    "restore_proxy",
    "disable_proxy",
    "reset_wininet_proxy",
    "restore_known_good_proxy",
}
DESTRUCTIVE_ACTION_TOKENS = (
    "firewall",
    "adapter_disable",
    "kill",
    "process_kill",
    "arbitrary_shell",
    "netsh_reset",
)


def _has(signals: dict[str, Any], name: str) -> bool:
    """Return whether a normalized signal is true."""
    value = signals.get(name)
    if isinstance(value, str):
        return value.strip().lower() in {
            "true",
            "yes",
            "ok",
            "success",
            "succeeded",
            "enabled",
            "1",
        }
    return bool(value)


def _event_ids_for(required: set[str], events: list[EndpointEvent]) -> list[str]:
    """Return event IDs matching required event types."""
    return [event.id for event in events if event.event_type in required]


def infer_browser_proxy_transitions(
    events: list[EndpointEvent], signals: dict[str, Any]
) -> list[StateTransition]:
    """Infer state transitions for the browser proxy path scenario."""
    observed = event_types(events)
    transitions: list[StateTransition] = []
    current = "healthy_browser_path"

    drift_events = {
        "wininet_proxy_changed",
        "wininet_proxy_enabled",
        "localhost_proxy_detected",
    } & observed
    if drift_events:
        transitions.append(
            StateTransition(
                from_state=current,
                to_state="proxy_drift_detected",
                rule_id="proxy_drift",
                confidence=0.72,
                event_ids=_event_ids_for(drift_events, events),
            )
        )
        current = "proxy_drift_detected"

    suspect_required = {
        "ping_ok",
        "dns_ok",
        "tcp443_ok",
        "browser_https_failed",
        "wininet_proxy_enabled",
    }
    if suspect_required.issubset(observed):
        transitions.append(
            StateTransition(
                from_state=current,
                to_state="browser_path_failure_suspected",
                rule_id="browser_path_suspected",
                confidence=0.84,
                event_ids=_event_ids_for(suspect_required, events),
            )
        )
        current = "browser_path_failure_suspected"

    confirmed_required = {"proxy_bypass_succeeded", "proxied_path_failed"}
    if confirmed_required.issubset(observed):
        transitions.append(
            StateTransition(
                from_state=current,
                to_state="proxy_path_failure_confirmed",
                rule_id="proxy_path_confirmed",
                confidence=0.92,
                evidence_level="validated",
                event_ids=_event_ids_for(confirmed_required, events),
            )
        )
        current = "proxy_path_failure_confirmed"

    if _has(signals, "policy_preview_allowed") and current == "proxy_path_failure_confirmed":
        transitions.append(
            StateTransition(
                from_state=current,
                to_state="remediation_preview_ready",
                rule_id="preview_ready",
                confidence=0.90,
                evidence_level="validated",
                event_ids=_event_ids_for({"policy_preview_allowed"}, events),
            )
        )
    return transitions


def reject_alternatives(signals: dict[str, Any]) -> list[dict[str, str]]:
    """Return alternative hypotheses rejected by observed positive controls."""
    rejected: list[dict[str, str]] = []
    if _has(signals, "ping_ok") or _has(signals, "dns_ok") or _has(signals, "tcp443_ok"):
        rejected.append(
            {"hypothesis": "total_network_outage", "reason": "ping/dns/tcp checks succeeded"}
        )
    if _has(signals, "dns_ok"):
        rejected.append({"hypothesis": "dns_only_failure", "reason": "dns resolution succeeded"})
    if _has(signals, "tcp443_ok"):
        rejected.append({"hypothesis": "tcp_blocked", "reason": "TCP 443 connectivity succeeded"})
    if _has(signals, "tcp443_ok") and _has(signals, "proxy_bypass_succeeded"):
        rejected.append(
            {
                "hypothesis": "upstream_isp_issue",
                "reason": "direct HTTPS path succeeded outside proxy",
            }
        )
    if _has(signals, "proxy_bypass_succeeded") and not _has(signals, "tls_certificate_error"):
        rejected.append(
            {
                "hypothesis": "certificate_tls_issue",
                "reason": "proxy bypass succeeded without TLS error signal",
            }
        )
    return rejected


def rank_hypotheses(
    *,
    transitions: list[StateTransition],
    signals: dict[str, Any],
    proof_result: ProofResult,
) -> list[dict[str, Any]]:
    """Rank competing hypotheses from events, transitions, and proof status."""
    score = 0.20
    evidence: list[str] = []
    for name in ("ping_ok", "dns_ok", "tcp443_ok", "browser_https_failed", "wininet_proxy_enabled"):
        if _has(signals, name):
            score += 0.10
            evidence.append(name)
    if _has(signals, "localhost_proxy_detected"):
        score += 0.08
        evidence.append("localhost_proxy_detected")
    if _has(signals, "proxy_bypass_succeeded") and _has(signals, "proxied_path_failed"):
        score += 0.18
        evidence.extend(["proxy_bypass_succeeded", "proxied_path_failed"])
    if proof_result.status == "CONFIRMED":
        score += 0.12
        evidence.append("proof_confirmed")
    if not transitions:
        score = min(score, 0.30)

    score = round(max(0.0, min(0.98, score)), 2)
    alternatives = reject_alternatives(signals)
    ranking = [
        {
            "hypothesis": "browser_proxy_path_regression",
            "confidence": score,
            "evidence": evidence,
            "state_depth": len(transitions),
        }
    ]
    ranking.extend(
        {
            "hypothesis": item["hypothesis"],
            "confidence": 0.10,
            "evidence": [item["reason"]],
            "rejected": True,
        }
        for item in alternatives
    )
    return ranking


def evaluate_reasoning_policy(
    *,
    hypothesis: str,
    transitions: list[StateTransition],
    proof_result: ProofResult,
    confidence: float,
    impact_level: str,
    requested_action: str | None,
    explicit_confirmation: bool = False,
    conflicting_signals: bool = False,
) -> PolicyDecision:
    """Map (hypothesis, transitions, proof, impact, action) to a typed :class:`PolicyDecision`.

    Decision intent:
        Decide whether the reasoning chain is strong enough to ALLOW a known-safe registry
        action, downgrade to PREVIEW for operator review, or BLOCK destructive paths. The
        function never executes remediation; it only emits the decision plus reason codes
        the audit log preserves.

    Args:
        hypothesis: Accepted hypothesis identifier (e.g. ``"browser_proxy_path_regression"``).
        transitions: Ordered :class:`StateTransition` list for this run; the last entry's
            ``to_state`` is reported as ``state_transition`` on the decision.
        proof_result: Outcome of the optional proof engine (status drives ALLOW eligibility).
        confidence: Ordinal hypothesis confidence in ``[0.0, 1.0]``; **not** a calibrated
            probability — used for explainability and audit trails only.
        impact_level: Reliability impact bucket (``"low"`` | ``"medium"`` | ``"high"`` |
            ``"critical"``); high/critical force PREVIEW unless proof is ``CONFIRMED``.
        requested_action: Optional remediation key. ``None`` returns a diagnostic-only
            ``PREVIEW`` decision. Substring matches in :data:`DESTRUCTIVE_ACTION_TOKENS`
            BLOCK unconditionally.
        explicit_confirmation: ``True`` when the operator typed the documented confirmation
            phrase via the CLI/API confirmation gate.
        conflicting_signals: ``True`` when normalized observations contain direct
            contradictions (e.g. ``browser_https_failed`` and ``browser_https_ok``).

    Returns:
        Immutable :class:`PolicyDecision` carrying ``outcome`` (``ALLOW`` | ``PREVIEW`` |
        ``BLOCK``), the resolved ``trust_level``/``evidence_level``, deduplicated
        ``reason_codes``, ``limitations``, and recommended next steps.

    Constraints and limitations:
        * Confidence alone never grants ALLOW — proof status and impact must align.
        * Unknown / unallowlisted action keys always BLOCK.
        * Tokens in :data:`DESTRUCTIVE_ACTION_TOKENS` BLOCK regardless of evidence.

    Audit Notes:
        This is the **single authoritative policy gate** for action evaluation. When an
        operator disputes ``outcome``:

        * What could go wrong: A widened ALLOW path could let a high-impact action through
          without proof. The defense-in-depth block (see ``# Defense-in-depth`` comment) is
          designed to catch this — every guardrail re-asserts ``outcome = "PREVIEW"`` rather
          than only annotating ``reason_codes``.
        * How to detect: ``reason_codes`` always carries the rule that fired; cross-check
          against ``outcome``. If ``outcome == "ALLOW"`` but a ``*_requires_*`` reason code
          is present, the gate has regressed.
        * How to recover: Re-run with the same inputs to verify determinism, then revert the
          offending change in this module or :mod:`platform_core.impact_score`.
        * Evidence available: Reason codes, limitations, and trust level are persisted on
          every reasoning run (``platform_data/audit.jsonl`` via callers).
    """
    action = (requested_action or "").strip().lower() or None
    reason_codes: list[str] = []
    limitations: list[str] = []
    state_transition = transitions[-1].to_state if transitions else "unknown"
    evidence_level = (
        "proof"
        if proof_result.status == "CONFIRMED"
        else ("validated" if transitions else "inferred")
    )
    trust_level = (
        "low"
        if conflicting_signals
        else ("high" if proof_result.status == "CONFIRMED" else "medium")
    )

    if action and any(token in action for token in DESTRUCTIVE_ACTION_TOKENS):
        return PolicyDecision(
            outcome="BLOCK",
            requested_action=action,
            hypothesis=hypothesis,
            state_transition=state_transition,
            evidence_level=evidence_level,  # type: ignore[arg-type]
            proof_status=proof_result.status,
            confidence=confidence,
            trust_level=trust_level,  # type: ignore[arg-type]
            impact_level=impact_level,  # type: ignore[arg-type]
            reason_codes=[pv2.DESTRUCTIVE_ACTION_BLOCKED],
            blocked_actions=pv2.blocked_actions_for_request(
                outcome="BLOCK", requested_action=action
            ),
            limitations=[
                "Firewall reset, adapter disable, process kill, and arbitrary shell remain blocked."
            ],
            recommended_next_steps=["Use manual incident response after preserving evidence."],
        )

    if not action:
        return PolicyDecision(
            outcome="PREVIEW",
            requested_action=None,
            hypothesis=hypothesis,
            state_transition=state_transition,
            evidence_level=evidence_level,  # type: ignore[arg-type]
            proof_status=proof_result.status,
            confidence=confidence,
            trust_level=trust_level,  # type: ignore[arg-type]
            impact_level=impact_level,  # type: ignore[arg-type]
            reason_codes=[pv2.DIAGNOSTIC_ONLY],
            blocked_actions=pv2.blocked_actions_for_request(
                outcome="PREVIEW", requested_action=None
            ),
            recommended_next_steps=[
                "Run preview with a safe remediation action if repair is needed."
            ],
        )

    if action not in SAFE_REGISTRY_ACTIONS:
        return PolicyDecision(
            outcome="BLOCK",
            requested_action=action,
            hypothesis=hypothesis,
            state_transition=state_transition,
            evidence_level=evidence_level,  # type: ignore[arg-type]
            proof_status=proof_result.status,
            confidence=confidence,
            trust_level=trust_level,  # type: ignore[arg-type]
            impact_level=impact_level,  # type: ignore[arg-type]
            reason_codes=[pv2.UNKNOWN_ACTION],
            blocked_actions=pv2.blocked_actions_for_request(
                outcome="BLOCK", requested_action=action
            ),
            limitations=["Only allowlisted remediation action keys can pass policy."],
            recommended_next_steps=[
                "Choose an allowlisted preview action or continue diagnostics."
            ],
        )

    if conflicting_signals:
        reason_codes.append(pv2.CONFLICTING_SIGNALS)
        limitations.append("Conflicting observations reduce trust; live execution is not allowed.")
        outcome = "PREVIEW"
    elif proof_result.status == "CONFIRMED" and explicit_confirmation:
        reason_codes.append(pv2.CONFIRMED_SAFE_TIER_WITH_CONFIRMATION)
        reason_codes.append(pv2.SAFE_TIER_ACTION)
        outcome = "ALLOW"
    else:
        reason_codes.append(pv2.REQUIRES_OPERATOR_CONFIRMATION)
        reason_codes.append(pv2.PREVIEW_UNTIL_PROOF)
        outcome = "PREVIEW"

    # Defense-in-depth: each impact/trust guardrail below MUST also enforce a
    # downgrade to PREVIEW, not just annotate `reason_codes`. Today the ALLOW
    # gate (the elif above) already requires CONFIRMED proof + no conflicts,
    # so these conditions are mutually exclusive with ALLOW. We still re-assert
    # the downgrade here so any future widening of the ALLOW gate cannot
    # silently bypass the impact policy.
    if impact_level in ("high", "critical") and proof_result.status != "CONFIRMED":
        reason_codes.append(pv2.HIGH_IMPACT_UNPROVEN)
        if outcome == "ALLOW":
            limitations.append(
                "High or critical reliability impact requires CONFIRMED proof before live execute."
            )
        outcome = "PREVIEW"
    if impact_level == "critical" and trust_level != "high":
        reason_codes.append(pv2.CRITICAL_IMPACT_LOW_TRUST)
        if outcome == "ALLOW":
            limitations.append(
                "Critical reliability impact requires high trust (CONFIRMED proof, no conflicting signals)."
            )
        outcome = "PREVIEW"

    if proof_result.status != "CONFIRMED":
        reason_codes.append(pv2.HIGH_CONFIDENCE_UNPROVEN)
        if outcome == "ALLOW":
            limitations.append(
                "Unproven hypothesis cannot grant execute authority even with high confidence."
            )
        outcome = "PREVIEW"
    if action in SAFE_REGISTRY_ACTIONS:
        reason_codes.append(pv2.REQUIRES_TYPED_CONFIRMATION)

    return PolicyDecision(
        outcome=outcome,  # type: ignore[arg-type]
        requested_action=action,
        hypothesis=hypothesis,
        state_transition=state_transition,
        evidence_level=evidence_level,  # type: ignore[arg-type]
        proof_status=proof_result.status,
        confidence=confidence,
        trust_level=trust_level,  # type: ignore[arg-type]
        impact_level=impact_level,  # type: ignore[arg-type]
        requires_confirmation=action in SAFE_REGISTRY_ACTIONS,
        confirmation_phrase="RESTORE_PROXY" if action in SAFE_REGISTRY_ACTIONS else None,
        reason_codes=list(dict.fromkeys(reason_codes)),
        blocked_actions=pv2.blocked_actions_for_request(
            outcome=outcome,  # type: ignore[arg-type]
            requested_action=action,
        ),
        limitations=limitations,
        recommended_next_steps=[
            "Show remediation preview and require typed operator confirmation."
        ],
    )


def _conflicting_signals(signals: dict[str, Any]) -> bool:
    """Return whether directly contradictory signals are present."""
    return (_has(signals, "browser_https_failed") and _has(signals, "browser_https_ok")) or (
        _has(signals, "dns_ok") and _has(signals, "dns_failed")
    )


def run_reasoning(
    observations: list[Observation],
    *,
    proof_result: ProofResult | None = None,
    requested_action: str | None = None,
    explicit_confirmation: bool = False,
    source: str = "reasoning_engine",
    run_id: str | None = None,
) -> ReasoningRun:
    """Drive the full deterministic Observation → Decision pipeline for endpoint reliability.

    Pipeline stages:
        1. ``normalize_signals`` — project raw observations into a canonical signal map.
        2. ``detect_endpoint_events`` — emit :class:`EndpointEvent` rows for matched signals.
        3. ``infer_browser_proxy_transitions`` — walk the state machine for proxy/browser path.
        4. ``rank_hypotheses`` — score candidate hypotheses; pick the top entry as accepted.
        5. ``calculate_reliability_impact`` — derive severity/scope and the impact bucket.
        6. :func:`evaluate_reasoning_policy` — gate the requested action against policy.
        7. ``build_evidence_tree`` — assemble an explainable, replay-friendly tree.

    Args:
        observations: Replayable observations. **No machine probes happen here**; the engine
            is pure with respect to its inputs.
        proof_result: Optional :class:`ProofResult` from a targeted checker (e.g. HTTPS
            proxy bypass contrast). Defaults to ``ProofResult(NOT_RUN)`` shape.
        requested_action: Optional remediation action key. See :data:`SAFE_REGISTRY_ACTIONS`
            for the allowlist.
        explicit_confirmation: ``True`` when the operator typed the documented confirmation
            phrase. Required (along with ``CONFIRMED`` proof and no conflicts) for ``ALLOW``.
        source: Free-form caller label persisted on the reasoning run for audit lookup.
        run_id: Optional stable identifier for replay parity. Generated when omitted.

    Returns:
        :class:`ReasoningRun` with events, transitions, hypothesis ranking, evidence tree,
        proof result, reliability impact, policy decision, recommended next test, and an
        optional remediation preview (only populated when ``policy.outcome == "PREVIEW"``).

    Side effects:
        None. Persistence and audit row writes are caller responsibilities.

    Idempotency:
        Calling :func:`run_reasoning` twice with identical arguments yields equivalent
        :class:`ReasoningRun` objects (the only divergence is auto-generated ``run_id`` /
        nested IDs when the caller omits them).

    Audit Notes:
        Use this function with the **stored observations** from
        ``platform_data/audit.jsonl`` to replay any historical decision without touching
        the host. Diverging output indicates a code change to scoring weights, scenario
        rules, impact buckets, or policy thresholds — review git history accordingly.
    """
    scenarios = default_failure_scenarios()
    proof = proof_result or ProofResult(hypothesis="browser_proxy_path_regression")
    rid = run_id or new_id("run")
    signals = normalize_signals(observations)
    events = detect_endpoint_events(observations)
    transitions = infer_browser_proxy_transitions(events, signals)
    canonical_transitions = infer_canonical_transitions(
        transitions, events=events, signals=signals
    )
    canonical_path = canonical_state_path(canonical_transitions)
    ranking = rank_hypotheses(transitions=transitions, signals=signals, proof_result=proof)
    accepted = ranking[0]["hypothesis"] if ranking else "unknown"
    confidence = float(ranking[0]["confidence"]) if ranking else 0.0
    rejected = reject_alternatives(signals)
    scenario = scenarios["browser_proxy_path_regression"]
    limitations = list(scenario.limitations)
    if _conflicting_signals(signals):
        limitations.append("Conflicting signals were observed; policy is downgraded to preview.")
    if proof.status == "NOT_RUN":
        limitations.append("Proof checks were not run; confidence remains heuristic.")

    severity = "high" if _has(signals, "browser_https_failed") else "medium"
    scope = "browser_and_dev_tools" if _has(signals, "proxied_path_failed") else "browser_only"
    impact = calculate_reliability_impact(
        severity=severity,  # type: ignore[arg-type]
        scope=scope,  # type: ignore[arg-type]
        confidence=confidence,
        duration_factor="unknown",
    )
    policy = evaluate_reasoning_policy(
        hypothesis=accepted,
        transitions=transitions,
        proof_result=proof,
        confidence=confidence,
        impact_level=impact.impact_level,
        requested_action=requested_action,
        explicit_confirmation=explicit_confirmation,
        conflicting_signals=_conflicting_signals(signals),
    )
    if policy.outcome == "PREVIEW":
        preview = {
            "action": requested_action,
            "dry_run": True,
            "requires_confirmation": policy.requires_confirmation,
            "confirmation_phrase": policy.confirmation_phrase,
        }
    else:
        preview = {}
    recommendations = list(
        dict.fromkeys(scenario.recommended_next_steps + policy.recommended_next_steps)
    )
    tree: EvidenceTree = build_evidence_tree(
        run_id=rid,
        accepted_hypothesis=accepted,
        events=events,
        transitions=transitions,
        rejected_alternatives=rejected,
        proof_result=proof,
        limitations=limitations + policy.limitations,
        recommended_next_steps=recommendations,
    )
    return ReasoningRun(
        id=rid,
        source=source,
        raw_observations=observations,
        normalized_signals=signals,
        detected_events=events,
        state_transitions=transitions,
        canonical_state_path=list(canonical_path),
        canonical_state_transitions=[
            item.model_dump(mode="json") for item in canonical_transitions
        ],
        hypothesis_ranking=ranking,
        accepted_hypothesis=accepted,
        evidence_tree=tree,
        proof_result=proof,
        reliability_impact=impact,
        policy_decision=policy,
        recommended_next_test="Run proxy bypass contrast proof if not already confirmed.",
        remediation_preview=preview,
        limitations=list(dict.fromkeys(limitations + proof.limitations + policy.limitations)),
        recommended_next_steps=recommendations,
    )


def observation(
    name: str, value: Any = True, *, source: str = "fixture", confidence: float = 1.0
) -> Observation:
    """Convenience constructor for tests and fixtures."""
    return Observation(
        source=source, signal_name=name, value=value, normalized_value=value, confidence=confidence
    )

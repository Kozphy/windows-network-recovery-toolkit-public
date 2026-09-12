"""Local-only agent next-step planner.

Module responsibility:
    Consume a structured :class:`~platform_core.product_contract.DiagnosisResult` (or any
    compatible mapping) plus optional probe-shape hints and emit a JSON-friendly
    recommendation describing **the next read-only probe or preview** the operator should
    run. Recommendations are bounded to a fixed set of safe actions; destructive actions
    are surfaced exclusively in :data:`BLOCKED_ACTIONS` so callers can verify the boundary.

System placement:
    Wired into ``src.command_handlers_safety.cmd_agent_next_step`` (CLI ``agent next-step``)
    and ``backend.platform_routes.agent_next_step`` (``POST /platform/agent/next-step``).
    The planner reads the latest stored diagnosis but never re-probes the host or invokes
    subprocesses.

Key invariants:
    * The agent **never mutates** Windows state, never spawns subprocesses, never touches
      registry, network, processes, certificates, or files.
    * :class:`AgentNextStep.next_step` is constrained to :data:`SafeNextStep` literal values.
    * :class:`AgentNextStep.blocked_actions` always equals :data:`BLOCKED_ACTIONS` so the
      caller / dashboard can show the policy boundary alongside the recommendation.

Input assumptions:
    * ``diagnosis`` is one of: ``DiagnosisResult``, plain ``dict``, or ``None``.
    * Observation rows expose ``name``, optional ``observed_value`` mapping, and a string
      ``status``. Pydantic ``model_dump`` is preferred when available.

Output guarantees:
    * Returned :class:`AgentNextStep` is JSON-serializable via :meth:`AgentNextStep.to_dict`.
    * ``confidence`` is clamped to ``[0.0, 1.0]``.
    * ``policy_boundary`` is always ``"recommendation_only_no_mutation"``.

Capabilities exposed via ``goal``:
    * ``suggest_next_probe`` (default)
    * ``rank_hypotheses``
    * ``explain_risk``
    * ``recommend_preview_action``
    * ``summarize_audit``
    * ``identify_missing_evidence``

Audit Notes:
    The planner writes nothing — its caller (CLI handler or FastAPI route) appends the audit
    row. When the agent's recommendation is disputed, capture the input ``DiagnosisResult``
    and ``goal`` and re-call :func:`plan_next_step`; the planner is deterministic, so
    divergent output indicates a code change to the rule set in this module.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

AgentGoal = Literal[
    "suggest_next_probe",
    "rank_hypotheses",
    "explain_risk",
    "recommend_preview_action",
    "summarize_audit",
    "identify_missing_evidence",
]

PolicyBoundary = Literal["recommendation_only_no_mutation"]
SafeNextStep = Literal[
    "run_diagnosis",
    "run_proxy_disable_preview",
    "inspect_node_process",
    "run_registry_writer_proof",
    "restart_browser",
    "collect_lkg",
    "compare_proxy_config",
    "review_audit",
]

BLOCKED_ACTIONS: tuple[str, ...] = (
    "process_kill",
    "firewall_reset",
    "adapter_disable",
    "adapter_reset",
    "winsock_reset",
    "certificate_delete",
    "broad_registry_cleanup",
    "arbitrary_shell",
)


@dataclass(frozen=True)
class AgentNextStep:
    """Bounded recommendation produced by :func:`plan_next_step`."""

    next_step: SafeNextStep
    reason: str
    evidence_used: list[str] = field(default_factory=list)
    confidence: float = 0.0
    policy_boundary: PolicyBoundary = "recommendation_only_no_mutation"
    blocked_actions: tuple[str, ...] = BLOCKED_ACTIONS

    def to_dict(self) -> dict[str, Any]:
        """Project the recommendation into a plain JSON-friendly dict.

        Returns:
            Mapping with ``next_step``, ``reason``, ``evidence_used`` (list copy),
            ``confidence`` (float), ``policy_boundary``, and ``blocked_actions``
            (list copy of :data:`BLOCKED_ACTIONS`).

        Notes:
            Lists are copied so the caller cannot mutate the frozen dataclass state.
        """
        return {
            "next_step": self.next_step,
            "reason": self.reason,
            "evidence_used": list(self.evidence_used),
            "confidence": float(self.confidence),
            "policy_boundary": self.policy_boundary,
            "blocked_actions": list(self.blocked_actions),
        }


def _coerce_observations(diagnosis: Any) -> list[dict[str, Any]]:
    """Project diagnosis observations into a list of plain dicts."""

    if diagnosis is None:
        return []
    if hasattr(diagnosis, "observations"):
        observations = diagnosis.observations or []
        out: list[dict[str, Any]] = []
        for probe in observations:
            if isinstance(probe, dict):
                out.append(probe)
            elif hasattr(probe, "model_dump"):
                out.append(probe.model_dump(mode="json"))
            else:
                out.append(
                    {
                        "name": getattr(probe, "name", ""),
                        "status": getattr(probe, "status", ""),
                        "observed_value": getattr(probe, "observed_value", None),
                    }
                )
        return out
    if isinstance(diagnosis, dict):
        raw = diagnosis.get("observations") or []
        return [item for item in raw if isinstance(item, dict)]
    return []


def _has_localhost_proxy(observations: list[dict[str, Any]]) -> bool:
    for probe in observations:
        if probe.get("name") != "wininet_proxy_state":
            continue
        observed = probe.get("observed_value")
        if not isinstance(observed, dict):
            continue
        server = str(observed.get("proxy_server") or "")
        if not server:
            continue
        lowered = server.lower()
        if "127.0.0.1" in lowered or "localhost" in lowered or "::1" in lowered:
            return True
    return False


def _proof_status(diagnosis: Any) -> str:
    if diagnosis is None:
        return "unknown"
    proof = getattr(diagnosis, "proof_status", None)
    if isinstance(proof, str) and proof:
        return proof
    if isinstance(diagnosis, dict):
        candidate = diagnosis.get("proof_status")
        if isinstance(candidate, str) and candidate:
            return candidate
    return "inconclusive"


def _confidence(diagnosis: Any) -> float:
    if diagnosis is None:
        return 0.0
    raw = getattr(diagnosis, "confidence", None)
    if raw is None and isinstance(diagnosis, dict):
        raw = diagnosis.get("confidence")
    try:
        return max(0.0, min(1.0, float(raw or 0.0)))
    except (TypeError, ValueError):
        return 0.0


def identify_missing_evidence(observations: Iterable[dict[str, Any]]) -> list[str]:
    """Return a deterministic list of missing-evidence descriptors."""

    seen = {str(probe.get("name") or "") for probe in observations}
    missing: list[str] = []
    if "wininet_proxy_state" not in seen:
        missing.append("wininet_proxy_state probe missing")
    if "localhost_proxy_listener" not in seen:
        missing.append("localhost_proxy_listener probe missing")
    if "https_probe" not in seen:
        missing.append("https_probe missing")
    return missing


def plan_next_step(diagnosis: Any, *, goal: AgentGoal = "suggest_next_probe") -> AgentNextStep:
    """Recommend the next read-only step from a stored diagnosis.

    Decision intent:
        Steer operators toward the next safe diagnostic or preview action — never toward a
        mutation. The function inspects observation names, proof status, and confidence
        from the supplied diagnosis to pick one of :data:`SafeNextStep` literals.

    Args:
        diagnosis: ``DiagnosisResult`` instance, plain dict, or ``None``. ``None`` triggers
            the ``run_diagnosis`` recommendation.
        goal: Bounded planner intent (see module docstring for the full set).

    Returns:
        :class:`AgentNextStep` with reason text, evidence list, clamped confidence, fixed
        policy boundary, and the immutable blocked-actions tuple.

    Side effects:
        None. The planner never spawns subprocesses, never reads files outside whatever the
        diagnosis already loaded, and never mutates Windows state.

    Idempotency:
        Pure function — same diagnosis + same goal always produces the same recommendation.

    Examples:
        >>> from platform_core.agent_planner import plan_next_step
        >>> step = plan_next_step(None)
        >>> step.next_step
        'run_diagnosis'

    Audit Notes:
        Recommendation only — never a remediation. The handler that calls
        :func:`plan_next_step` is responsible for appending the audit row that records the
        recommendation, the operator's goal, and the blocked-action boundary.
    """

    observations = _coerce_observations(diagnosis)
    proof_status = _proof_status(diagnosis)
    confidence = _confidence(diagnosis)
    has_localhost_proxy = _has_localhost_proxy(observations)
    evidence_used = [str(probe.get("name") or "") for probe in observations if probe.get("name")]

    if diagnosis is None:
        return AgentNextStep(
            next_step="run_diagnosis",
            reason="No stored diagnosis was found; run a read-only diagnosis first.",
            evidence_used=[],
            confidence=0.2,
        )

    if goal == "summarize_audit":
        return AgentNextStep(
            next_step="review_audit",
            reason="Review the latest audit row alongside the recommended preview before any mutation.",
            evidence_used=evidence_used,
            confidence=confidence,
        )
    if goal == "identify_missing_evidence":
        gaps = identify_missing_evidence(observations)
        if gaps:
            return AgentNextStep(
                next_step="run_diagnosis",
                reason="; ".join(gaps),
                evidence_used=evidence_used,
                confidence=max(0.2, confidence),
            )
        return AgentNextStep(
            next_step="compare_proxy_config",
            reason="No critical evidence gaps detected; compare WinINET, WinHTTP, Git, npm, env proxy posture next.",
            evidence_used=evidence_used,
            confidence=confidence,
        )

    if has_localhost_proxy and proof_status.lower() in {"inconclusive", "unknown", "not_run"}:
        return AgentNextStep(
            next_step="run_registry_writer_proof",
            reason=(
                "WinINET points to a localhost proxy and registry writer proof is not yet conclusive; "
                "run the read-only Sysmon registry-writer adapter before any remediation."
            ),
            evidence_used=evidence_used
            + ["localhost_proxy_detected", f"proof_status={proof_status}"],
            confidence=max(confidence, 0.7),
        )

    if goal == "recommend_preview_action" and confidence >= 0.6:
        return AgentNextStep(
            next_step="run_proxy_disable_preview",
            reason="High confidence in proxy-path drift; request a dry-run proxy disable preview only.",
            evidence_used=evidence_used,
            confidence=confidence,
        )

    if goal == "explain_risk":
        return AgentNextStep(
            next_step="compare_proxy_config",
            reason=f"Risk signal aggregated to confidence {confidence:.2f}; review proxy config drift before any change.",
            evidence_used=evidence_used,
            confidence=confidence,
        )

    if goal == "rank_hypotheses":
        return AgentNextStep(
            next_step="compare_proxy_config",
            reason="Top hypothesis is proxy/browser-path drift; compare proxy surfaces to corroborate.",
            evidence_used=evidence_used,
            confidence=confidence,
        )

    if has_localhost_proxy:
        return AgentNextStep(
            next_step="inspect_node_process",
            reason="Localhost proxy listener present; inspect listener owner without mutating system state.",
            evidence_used=evidence_used,
            confidence=max(confidence, 0.55),
        )

    return AgentNextStep(
        next_step="compare_proxy_config",
        reason="Continue read-only validation: compare WinINET, WinHTTP, Git, npm, env proxy posture.",
        evidence_used=evidence_used,
        confidence=max(confidence, 0.4),
    )

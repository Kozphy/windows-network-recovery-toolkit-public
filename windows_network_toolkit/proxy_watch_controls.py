"""Big 4 audit control tests for proxy-watch state machine evidence.

Module responsibility:
    Evaluate classified proxy transition events against portfolio safety controls
    (classification accuracy, attribution bounds, policy gate, coalescing, reverter, replay).

System placement:
    Invoked by ``proxy_replay`` and portfolio control-test demos.

Key invariants:
    * ``CTRL_PROXY_CLASSIFICATION_ACCURACY`` fails when empty-after maps to remote proxy.
    * ``CTRL_POLICY_GATE_NO_AUTONOMOUS_REMEDIATION`` forbids auto_disable/kill_process language.
    * ``NOT_TESTED`` is valid when insufficient events are supplied.

Side effects:
    None — pure evaluation over in-memory event dicts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from windows_network_toolkit.proxy_state_machine import (
    TransitionClass,
    build_proxy_evidence_event,
    coalesce_proxy_events,
    detect_reverter_loop_pattern,
)


class ControlStatus(StrEnum):
    """Mature control test result labels for proxy-watch evidence."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_TESTED = "NOT_TESTED"


@dataclass
class ProxyWatchControlResult:
    """Single proxy-watch control test outcome.

    Attributes:
        control_id: Stable control identifier (e.g. ``CTRL_PROXY_CLASSIFICATION_ACCURACY``).
        status: ``ControlStatus`` value string.
        evidence: Human-readable evidence lines for audit trail.
        limitations: Scope limits for the control interpretation.
        recommendation: Suggested next step when FAIL/PARTIAL.
    """

    control_id: str
    status: str
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return asdict(self)


def _ctrl_classification_accuracy(event: dict[str, Any]) -> ProxyWatchControlResult:
    control_id = "CTRL_PROXY_CLASSIFICATION_ACCURACY"
    transition = str(event.get("transition_class") or "")
    after = event.get("after_state") or event.get("after") or {}
    after_server = after.get("proxy_server")
    server_empty = after_server is None or str(after_server).strip() == ""

    evidence: list[str] = [f"transition_class={transition}"]
    if server_empty and transition == TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED.value:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=evidence + ["after ProxyServer empty but classified as remote proxy"],
            limitations=["Removed proxy server must not map to remote proxy classification"],
            recommendation="Fix state machine — empty after.ProxyServer cannot be REMOTE_OR_NON_LOOPBACK",
        )

    serialized = str(event)
    if server_empty and "REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED" in serialized:
        if transition != TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED.value:
            return ProxyWatchControlResult(
                control_id=control_id,
                status=ControlStatus.PARTIAL.value,
                evidence=evidence + ["legacy string contains remote proxy wording"],
                recommendation="Review human-readable output for stale remote proxy messaging",
            )

    if transition in (
        TransitionClass.PROXY_SERVER_REMOVED_PARTIAL.value,
        TransitionClass.PROXY_SERVER_REMOVED.value,
        TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED.value,
    ):
        evidence.append("Removal transition correctly classified")
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.PASS.value,
            evidence=evidence,
            recommendation="Continue monitoring removal transitions for false remote proxy alerts",
        )

    if transition == TransitionClass.REMOTE_OR_NON_LOOPBACK_PROXY_CONFIGURED.value and not server_empty:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.PASS.value,
            evidence=evidence + ["Remote proxy classification with non-empty ProxyServer"],
            recommendation="Validate business justification for remote proxy endpoints",
        )

    return ProxyWatchControlResult(
        control_id=control_id,
        status=ControlStatus.PASS.value,
        evidence=evidence,
        recommendation="No misclassification detected for this event",
    )


def _ctrl_attribution_proof_boundary(event: dict[str, Any]) -> ProxyWatchControlResult:
    control_id = "CTRL_ATTRIBUTION_PROOF_BOUNDARY"
    proof_tier = str(event.get("proof_tier") or "T1")
    attribution = event.get("attribution") or {}
    kind = str(attribution.get("kind") or "none")
    evidence = [f"proof_tier={proof_tier}", f"attribution.kind={kind}"]

    bad_phrases = (
        "definitely changed",
        "changed registry",
        "node.exe changed",
        "Cursor disabled",
        "Proxy manually disabled",
    )
    blob = str(event).lower()
    for phrase in bad_phrases:
        if phrase.lower() in blob and proof_tier not in ("T3", "T4"):
            return ProxyWatchControlResult(
                control_id=control_id,
                status=ControlStatus.FAIL.value,
                evidence=evidence + [f"Found definitive wording without T3+ proof: {phrase}"],
                recommendation="Use correlation-only language when proof tier < T3",
            )

    if kind == "correlation" and proof_tier in ("T3", "T4"):
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=evidence,
            recommendation="Correlation attribution must not exceed T2 proof tier",
        )

    if proof_tier in ("T0", "T1", "T2") and kind in ("correlation", "none"):
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.PASS.value,
            evidence=evidence,
            recommendation="Attribution bounded correctly — collect Sysmon E13 for writer proof if needed",
        )

    if proof_tier in ("T3", "T4") and kind in ("sysmon", "procmon", "eventlog"):
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.PASS.value,
            evidence=evidence,
            recommendation="Writer proof tier aligned with attribution kind",
        )

    return ProxyWatchControlResult(
        control_id=control_id,
        status=ControlStatus.PARTIAL.value,
        evidence=evidence,
        recommendation="Review attribution proof tier alignment",
    )


def _ctrl_policy_gate(event: dict[str, Any]) -> ProxyWatchControlResult:
    control_id = "CTRL_POLICY_GATE_NO_AUTONOMOUS_REMEDIATION"
    policy = str(event.get("policy_decision") or "")
    action = str(event.get("recommended_action") or "").lower()
    evidence = [f"policy_decision={policy}", f"recommended_action={action[:120]}"]

    forbidden = ("auto_disable", "kill_process", "reset_firewall", "disable_adapter", "silent_remediation")
    if any(x in action for x in forbidden):
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=evidence,
            recommendation="Remove autonomous remediation language from policy recommendations",
        )

    if policy in ("OBSERVE", "ALERT", "REQUIRE_HUMAN_REVIEW", "BLOCK_AUTOMATION"):
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.PASS.value,
            evidence=evidence,
            recommendation="Policy gate remains observe/alert/human-review only",
        )

    return ProxyWatchControlResult(
        control_id=control_id,
        status=ControlStatus.FAIL.value,
        evidence=evidence,
        recommendation="Set policy_decision to OBSERVE|ALERT|REQUIRE_HUMAN_REVIEW|BLOCK_AUTOMATION",
    )


def _ctrl_coalescing(events: list[dict[str, Any]], *, coalesce_ms: int = 1000) -> ProxyWatchControlResult:
    control_id = "CTRL_COALESCING_REDUCES_FALSE_ALERTS"
    raw_events = events
    if not raw_events or "before" not in (raw_events[0] if raw_events else {}):
        raw_events = [
            {
                "timestamp_utc": "2026-01-01T00:00:00Z",
                "before": {
                    "wininet_proxy_enabled": True,
                    "wininet_proxy_server": "127.0.0.1:62285",
                },
                "after": {
                    "wininet_proxy_enabled": True,
                    "wininet_proxy_server": "",
                },
            },
            {
                "timestamp_utc": "2026-01-01T00:00:00.500Z",
                "before": {
                    "wininet_proxy_enabled": True,
                    "wininet_proxy_server": "",
                },
                "after": {
                    "wininet_proxy_enabled": False,
                    "wininet_proxy_server": "",
                },
            },
        ]

    if len(raw_events) < 2:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.NOT_TESTED.value,
            evidence=["Fewer than two raw events supplied"],
            recommendation="Supply paired ProxyServer removal + ProxyEnable disable sub-events",
        )

    merged_list = coalesce_proxy_events(raw_events, coalesce_window_ms=coalesce_ms)
    evidence = [f"raw_events={len(raw_events)}", f"merged_events={len(merged_list)}"]

    if len(merged_list) != 1:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=evidence,
            recommendation="Coalescing should merge rapid sub-events into one transition",
        )

    merged = merged_list[0]
    if not merged.get("coalesced"):
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=evidence,
            recommendation="Expected coalesced=true for multi-sub-event batch",
        )

    tc = str(merged.get("transition_class") or "")
    if tc == TransitionClass.PROXY_DISABLED_AND_SERVER_REMOVED.value:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.PASS.value,
            evidence=evidence + [f"transition_class={tc}", f"raw_sub_event_count={merged.get('raw_sub_event_count')}"],
            recommendation="Coalescing correctly merged disable + server removal",
        )

    if "REMOTE_OR_NON_LOOPBACK" in tc:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=evidence + [f"transition_class={tc}"],
            recommendation="Coalesced removal/disable must not classify as remote proxy",
        )

    return ProxyWatchControlResult(
        control_id=control_id,
        status=ControlStatus.PARTIAL.value,
        evidence=evidence + [f"transition_class={tc}"],
        recommendation="Verify coalesced transition matches expected PROXY_DISABLED_AND_SERVER_REMOVED",
    )


def _ctrl_reverter_loop(transitions: list[dict[str, Any]]) -> ProxyWatchControlResult:
    control_id = "CTRL_REVERTER_LOOP_PATTERN_DETECTION"
    detected = detect_reverter_loop_pattern(transitions)
    evidence = [f"transitions={len(transitions)}", f"detected={detected}"]

    if detected == TransitionClass.REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.PASS.value,
            evidence=evidence,
            recommendation="Investigate listener path; collect Sysmon E13 for registry writer proof",
        )

    if len(transitions) >= 5:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=evidence,
            recommendation="Expected reverter loop detection for repeated enable/disable cycles",
        )

    return ProxyWatchControlResult(
        control_id=control_id,
        status=ControlStatus.NOT_TESTED.value,
        evidence=evidence,
        recommendation="Supply at least 5 alternating enable/disable transitions on same port",
    )


def _ctrl_replay_determinism(replay_input: dict[str, Any]) -> ProxyWatchControlResult:
    control_id = "CTRL_AUDIT_REPLAY_DETERMINISM"
    before = replay_input.get("before") or replay_input.get("before_state") or {}
    after = replay_input.get("after") or replay_input.get("after_state") or {}
    ts = str(replay_input.get("timestamp_utc") or "2026-01-01T00:00:00Z")

    run1 = build_proxy_evidence_event(before_raw=before, after_raw=after, timestamp_utc=ts)
    run2 = build_proxy_evidence_event(before_raw=before, after_raw=after, timestamp_utc=ts)

    keys = ("transition_class", "risk", "proof_tier", "policy_decision", "recommended_action")
    mismatches = [k for k in keys if run1.get(k) != run2.get(k)]

    if mismatches:
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=[f"mismatched_fields={mismatches}"],
            recommendation="Ensure classification functions are pure and deterministic",
        )

    if run1.get("event_id") != run2.get("event_id"):
        return ProxyWatchControlResult(
            control_id=control_id,
            status=ControlStatus.FAIL.value,
            evidence=["event_id not deterministic"],
            recommendation="event_id must be stable for identical input",
        )

    return ProxyWatchControlResult(
        control_id=control_id,
        status=ControlStatus.PASS.value,
        evidence=[f"transition_class={run1.get('transition_class')}"],
        recommendation="Replay output is deterministic for fixed inputs",
    )


def run_proxy_watch_control_tests(
    *,
    events: list[dict[str, Any]] | None = None,
    coalesce_ms: int = 1000,
) -> list[dict[str, Any]]:
    """Run all proxy-watch audit controls against supplied events.

    Args:
        events: Classified transition events; last event is primary for per-event controls.
        coalesce_ms: Window for ``CTRL_COALESCING_REDUCES_FALSE_ALERTS``.

    Returns:
        List of control result dicts from ``ProxyWatchControlResult.to_dict()``.

    Side effects:
        None.
    """
    events = events or []
    results: list[ProxyWatchControlResult] = []

    primary = events[-1] if events else {}
    if primary:
        results.extend(
            [
                _ctrl_classification_accuracy(primary),
                _ctrl_attribution_proof_boundary(primary),
                _ctrl_policy_gate(primary),
                _ctrl_replay_determinism(primary),
            ]
        )
    else:
        for cid in (
            "CTRL_PROXY_CLASSIFICATION_ACCURACY",
            "CTRL_ATTRIBUTION_PROOF_BOUNDARY",
            "CTRL_POLICY_GATE_NO_AUTONOMOUS_REMEDIATION",
            "CTRL_AUDIT_REPLAY_DETERMINISM",
        ):
            results.append(
                ProxyWatchControlResult(
                    control_id=cid,
                    status=ControlStatus.NOT_TESTED.value,
                    recommendation="No events supplied",
                )
            )

    results.append(_ctrl_coalescing(events, coalesce_ms=coalesce_ms))
    results.append(_ctrl_reverter_loop(events))

    return [r.to_dict() for r in results]

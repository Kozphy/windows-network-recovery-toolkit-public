"""High-level observability event recorders — metrics + structured logs."""

from __future__ import annotations

from src.platform_core.operability.context import new_audit_id, set_audit_id
from src.platform_core.operability.metrics_registry import (
    METRIC_AGENT_HEARTBEAT,
    METRIC_AUDIT_APPENDED,
    METRIC_BLOCKED_ACTIONS,
    METRIC_CONTROL_TESTS_EXECUTED,
    METRIC_EVIDENCE_COLLECTED,
    METRIC_INCIDENTS_CLASSIFIED,
    METRIC_POLICY_DECISIONS,
    METRIC_REMEDIATION_PREVIEWS,
    METRIC_SPOOL_DEPTH,
    inc_counter,
    set_gauge,
)
from src.platform_core.operability.structured_logging import log_json


def record_evidence_collected(*, endpoint_id: str | None = None, source: str = "agent") -> None:
    """Record evidence collected.

    Args:
        endpoint_id: endpoint id supplied by the caller.
        source: source supplied by the caller.

    Returns:
        None.

    Side effects:
        Records data in the configured store or telemetry sink.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    inc_counter(METRIC_EVIDENCE_COLLECTED, labels={"source": source})
    log_json(
        "info",
        "evidence_collected",
        event_kind="evidence_collected",
        endpoint_id=endpoint_id,
        source=source,
        read_only=True,
    )


def record_incident_classified(*, classification: str, incident_id: str | None = None) -> None:
    """Record incident classified.

    Args:
        classification: classification supplied by the caller.
        incident_id: incident id supplied by the caller.

    Returns:
        None.

    Side effects:
        Records data in the configured store or telemetry sink.
    """
    inc_counter(METRIC_INCIDENTS_CLASSIFIED, labels={"classification": classification})
    log_json(
        "info",
        "incident_classified",
        event_kind="incident_classified",
        classification=classification,
        incident_id=incident_id,
    )


def record_control_test_executed(*, control_id: str, result: str) -> None:
    """Record control test executed.

    Args:
        control_id: control id supplied by the caller.
        result: result supplied by the caller.

    Returns:
        None.

    Side effects:
        Records data in the configured store or telemetry sink.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    inc_counter(
        METRIC_CONTROL_TESTS_EXECUTED,
        labels={"control_id": control_id, "result": result},
    )
    log_json(
        "info",
        "control_test_executed",
        event_kind="control_test_executed",
        control_id=control_id,
        result=result,
    )


def record_policy_decision(*, decision: str, action_id: str | None = None) -> None:
    """Record policy decision.

    Args:
        decision: decision supplied by the caller.
        action_id: action id supplied by the caller.

    Returns:
        None.

    Side effects:
        Records data in the configured store or telemetry sink.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    inc_counter(METRIC_POLICY_DECISIONS, labels={"decision": decision})
    log_json(
        "info",
        "policy_decision",
        event_kind="policy_decision",
        decision=decision,
        action_id=action_id,
    )


def record_blocked_action(*, action_id: str, reason: str = "policy_gate") -> None:
    """Record blocked action.

    Args:
        action_id: action id supplied by the caller.
        reason: reason supplied by the caller.

    Returns:
        None.

    Side effects:
        Records data in the configured store or telemetry sink.
    """
    inc_counter(METRIC_BLOCKED_ACTIONS, labels={"action_id": action_id})
    log_json(
        "warning",
        "blocked_action",
        event_kind="blocked_action",
        action_id=action_id,
        reason=reason,
    )


def record_remediation_preview(*, action_id: str, dry_run: bool = True) -> None:
    """Record remediation preview.

    Args:
        action_id: action id supplied by the caller.
        dry_run: dry run supplied by the caller.

    Returns:
        None.

    Side effects:
        Records data in the configured store or telemetry sink.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    inc_counter(METRIC_REMEDIATION_PREVIEWS, labels={"action_id": action_id})
    log_json(
        "info",
        "remediation_preview",
        event_kind="remediation_preview",
        action_id=action_id,
        dry_run=dry_run,
    )


def record_audit_appended(
    *,
    path: str | None = None,
    audit_id: str | None = None,
    trace_id: str | None = None,
) -> str:
    """Record audit/spool append; returns the audit_id used."""
    aid = audit_id or new_audit_id()
    set_audit_id(aid)
    inc_counter(METRIC_AUDIT_APPENDED)
    log_json(
        "info",
        "audit_appended",
        event_kind="audit_appended",
        audit_id=aid,
        trace_id=trace_id,
        path=path,
    )
    return aid


def record_agent_heartbeat(*, endpoint_id: str | None = None, health: str = "ok") -> None:
    """Record agent heartbeat.

    Args:
        endpoint_id: endpoint id supplied by the caller.
        health: health supplied by the caller.

    Returns:
        None.

    Side effects:
        Records data in the configured store or telemetry sink.
    """
    inc_counter(METRIC_AGENT_HEARTBEAT)
    log_json(
        "info",
        "agent_heartbeat",
        event_kind="agent_heartbeat",
        endpoint_id=endpoint_id,
        health=health,
        read_only=True,
    )


def update_spool_queue_depth(depth: int) -> None:
    """Return update spool queue depth.

    Args:
        depth: depth supplied by the caller.

    Returns:
        None.

    Side effects:
        None.
    """
    set_gauge(METRIC_SPOOL_DEPTH, float(max(0, depth)))
    log_json("debug", "spool_queue_depth", event_kind="spool_queue_depth", depth=depth)

"""Control objective models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ControlObjective(BaseModel):
    """Represent the control objective type.

    Key fields:
        control_id: Structured value carried by this type.
        name: Structured value carried by this type.
        control_type: Structured value carried by this type.
        description: Structured value carried by this type.
        owner: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    control_id: str
    name: str
    control_type: str
    description: str
    owner: str = "IT Governance"


def controls_for_fixture(_fixture: dict[str, Any]) -> list[ControlObjective]:
    """Return controls for fixture.

    Args:
        _fixture: fixture supplied by the caller.

    Returns:
        The computed `list[ControlObjective]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return [
        ControlObjective(
            control_id="CTRL_PROXY_MONITOR",
            name="Proxy configuration monitoring and drift detection",
            control_type="detective",
            description="Compare WinINET, WinHTTP, listener state, and direct/proxied path.",
            owner="IT Operations",
        ),
        ControlObjective(
            control_id="CTRL_WRITER_ATTRIBUTION",
            name="Registry writer attribution",
            control_type="detective",
            description="Correlate proxy registry changes with process writer telemetry (e.g. Sysmon E13).",
            owner="Security Operations / IT Risk",
        ),
        ControlObjective(
            control_id="CTRL_TLS_CONTRAST",
            name="TLS path contrast",
            control_type="detective",
            description="Compare certificate chain on direct vs proxied HTTPS paths.",
            owner="Security / GRC",
        ),
        ControlObjective(
            control_id="CTRL_REMEDIATION_GOVERNANCE",
            name="Policy-gated remediation",
            control_type="preventive",
            description="Dry-run default, typed confirmation, rollback review, no silent destructive actions.",
            owner="Platform Engineering / IT Governance",
        ),
        ControlObjective(
            control_id="CTRL_AUDIT_TRAIL",
            name="Append-only audit trail",
            control_type="detective",
            description="Hash-chained JSONL audit with deterministic replay.",
            owner="Internal Audit / Risk Advisory",
        ),
    ]

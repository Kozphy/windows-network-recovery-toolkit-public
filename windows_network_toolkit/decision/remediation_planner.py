"""Remediation planning: produce dry-run previews from a ``DecisionResult``.

Module responsibility:
    Map a completed ``DecisionResult`` to a set of remediation previews by
    consulting the ``windows_network_toolkit.remediation`` preview functions.
    Always returns preview-only output by default; live execution requires an
    explicit typed confirmation token delivered through a separate execution path.

System placement:
    Called by ``windows_network_toolkit.pipeline`` after ``evaluate_incident``
    and policy evaluation.  Previews are included in the pipeline result and
    surfaced via the ``/platform/diagnose`` and ``/platform/replay`` API
    responses.

Key invariants:
    * ``dry_run=True`` is the default and must be preserved unless the caller
      explicitly passes ``dry_run=False`` with a valid confirmation token.
    * This module never executes any remediation action — it calls only the
      ``preview_*`` functions from ``windows_network_toolkit.remediation``.
    * Actions in ``blocked_actions`` originate from the ``DecisionResult``
      populated by the policy engine, not from this planner.

Side effects:
    None — all ``preview_*`` functions are read-only and return dict previews.

Failure modes:
    ``preview_*`` function exceptions propagate to the caller; the planner
    does not catch them.
"""

from __future__ import annotations

from typing import Any

from windows_network_toolkit.remediation import (
    preview_dns_flush,
    preview_proxy_disable,
    preview_rollback,
    preview_stop_listener,
    preview_stop_reverter,
)

from .decision_model import DecisionResult, IncidentType


def plan_remediation(decision: DecisionResult, *, dry_run: bool = True) -> dict[str, Any]:
    """Build a remediation preview plan from a ``DecisionResult``.

    Selects the appropriate ``preview_*`` functions based on the incident type
    and appends them to a structured plan dict.  A rollback preview is always
    included.

    Args:
        decision: The ``DecisionResult`` produced by ``evaluate_incident``.
        dry_run: When ``True`` (default), all previews are marked as
            preview-only; no system state is changed.  Must remain ``True``
            unless explicit confirmation has been obtained via the platform
            remediation execute path.

    Returns:
        A dict with keys:

        * ``"dry_run"`` — echoes the ``dry_run`` flag.
        * ``"previews"`` — list of ``preview_*`` result dicts.
        * ``"rollback_plan"`` — rollback preview dict.
        * ``"allowed_actions"`` — sorted list of permitted action tokens.
        * ``"blocked_actions"`` — sorted list of blocked action tokens.
    """
    previews: list[dict[str, Any]] = []
    blocked = list(decision.blocked_actions)
    allowed = list(decision.allowed_actions)

    if decision.incident_type in {
        IncidentType.WININET_PROXY_DRIFT,
        IncidentType.PROXY_PATH_FAIL_DIRECT_PATH_SUCCESS,
    }:
        previews.append(preview_proxy_disable(dry_run=dry_run))
        allowed.append("disable_wininet_proxy")

    if decision.incident_type == IncidentType.WRITER_AND_LISTENER_MATCH:
        previews.append(preview_stop_listener(dry_run=dry_run))
        previews.append(preview_stop_reverter(dry_run=dry_run))

    if decision.incident_type == IncidentType.DNS_OK_BROWSER_FAIL:
        previews.append(preview_dns_flush(dry_run=dry_run))

    rollback = preview_rollback(dry_run=dry_run)

    return {
        "dry_run": dry_run,
        "previews": previews,
        "rollback_plan": rollback,
        "allowed_actions": sorted(set(allowed)),
        "blocked_actions": sorted(set(blocked)),
    }

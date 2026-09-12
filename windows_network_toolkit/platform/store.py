"""In-memory session store for the most recent ERP pipeline result.

Module responsibility:
    Provide a lightweight process-local store that holds the last pipeline
    result so that ``/platform/decision/latest`` and
    ``/platform/evidence/timeline`` can serve cached data without re-running
    the pipeline.

System placement:
    Written by ``platform.api`` route handlers after each ``/platform/diagnose``
    or ``/platform/replay`` call.  Read by the ``latest`` and ``timeline``
    endpoints.  Not persisted — data is lost on process restart.

Key invariants:
    * The store is a module-level dict (process-local); it is not thread-safe
      for concurrent writes, but the single-threaded demo/local-replay use
      case does not require locking.
    * ``set_latest`` overwrites the entire store on each call — only the most
      recent pipeline result is retained.
    * ``get_timeline`` returns an empty list (not ``None``) when no result has
      been stored, ensuring callers always receive a safe iterable.

Side effects:
    Module-level ``_latest`` dict is mutated by ``set_latest``.

Failure modes:
    ``set_latest`` assumes the result object exposes ``bundle.incident_id``,
    ``timeline``, ``decision``, ``policy``, ``remediation``, and
    ``audit_record``; missing attributes raise ``AttributeError``.
"""

from __future__ import annotations

from typing import Any

_latest: dict[str, Any] = {}


def set_latest(result: Any) -> None:
    """Store the latest pipeline result in the in-memory session store.

    Overwrites any previously stored result.  Extracts the fields needed by
    the ``/platform/*`` read endpoints from the pipeline result object.

    Args:
        result: A pipeline result object exposing ``bundle``, ``timeline``,
            ``decision``, ``policy``, ``remediation``, and ``audit_record``
            attributes.

    Side effects:
        Mutates the module-level ``_latest`` dict.
    """
    global _latest
    _latest = {
        "incident_id": result.bundle.incident_id,
        "timeline": result.timeline,
        "decision": result.decision.model_dump(),
        "policy": result.policy,
        "remediation": result.remediation,
        "audit": result.audit_record,
    }


def get_latest() -> dict[str, Any]:
    """Return a shallow copy of the stored pipeline result dict.

    Returns:
        A copy of the latest stored result, or an empty dict when no pipeline
        run has been recorded yet.
    """
    return dict(_latest)


def get_timeline() -> list[dict[str, Any]]:
    """Return the timeline list from the latest stored pipeline result.

    Returns:
        The ``"timeline"`` list from the stored result, or an empty list when
        the store is empty or the timeline is absent.
    """
    return list(_latest.get("timeline") or [])

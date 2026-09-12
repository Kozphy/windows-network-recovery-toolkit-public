"""Local observability context — trace_id and audit_id propagation (no external deps).

Module responsibility:
    Bind ``trace_id`` and ``audit_id`` into ``contextvars`` for structured logging and
    metrics correlation across a single request or agent cycle.

System placement:
    Used by ``windows_network_toolkit/agent/read_only.py``, ``src/logging/audit.py``,
    and ``backend/main.py`` middleware when operability is enabled.

Key invariants:
    * Context is task-local — async workers must enter ``observability_scope`` per job.
    * IDs are opaque strings (UUID hex / UUID str); not guaranteed globally unique across
      processes without external coordination.

Side effects:
    None — only mutates contextvars for the current execution context.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token

_trace_id: ContextVar[str | None] = ContextVar("wnrt_trace_id", default=None)
_audit_id: ContextVar[str | None] = ContextVar("wnrt_audit_id", default=None)


def new_trace_id() -> str:
    """Generate a new trace identifier (UUID hex)."""
    return uuid.uuid4().hex


def new_audit_id() -> str:
    """Generate a new audit record identifier (UUID string)."""
    return str(uuid.uuid4())


def get_trace_id() -> str | None:
    """Return the active trace_id from context, if any."""
    return _trace_id.get()


def get_audit_id() -> str | None:
    """Return the active audit_id from context, if any."""
    return _audit_id.get()


def set_trace_id(value: str | None) -> Token[str | None]:
    """Bind trace_id into the current context."""
    return _trace_id.set(value)


def set_audit_id(value: str | None) -> Token[str | None]:
    """Bind audit_id into the current context."""
    return _audit_id.set(value)


def reset_trace_id(token: Token[str | None]) -> None:
    """Reset trace id.

    Args:
        token: token supplied by the caller.

    Returns:
        None.

    Side effects:
        Updates process-local or test-scoped state.
    """
    _trace_id.reset(token)


def reset_audit_id(token: Token[str | None]) -> None:
    """Reset audit id.

    Args:
        token: token supplied by the caller.

    Returns:
        None.

    Side effects:
        Updates process-local or test-scoped state.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    _audit_id.reset(token)


@contextmanager
def observability_scope(
    *,
    trace_id: str | None = None,
    audit_id: str | None = None,
) -> Iterator[tuple[str, str | None]]:
    """Bind trace_id (and optional audit_id) for the duration of a pipeline step.

    Yields:
        ``(trace_id, audit_id)`` — ``audit_id`` may be ``None`` until explicitly set.
    """
    tid = trace_id or new_trace_id()
    trace_token = set_trace_id(tid)
    audit_token: Token[str | None] | None = None
    if audit_id is not None:
        audit_token = set_audit_id(audit_id)
    try:
        yield tid, audit_id
    finally:
        reset_trace_id(trace_token)
        if audit_token is not None:
            reset_audit_id(audit_token)


def correlation_fields() -> dict[str, str]:
    """Return trace/audit ids for log and spool payloads (omit missing keys)."""
    out: dict[str, str] = {}
    tid = get_trace_id()
    aid = get_audit_id()
    if tid:
        out["trace_id"] = tid
    if aid:
        out["audit_id"] = aid
    return out

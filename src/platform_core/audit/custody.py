"""Unified custody events — hash-chained audit + tip anchor for proxy/remediation paths."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.platform_core.audit.paths import default_canonical_path
from src.platform_core.contracts import AuditActionType

# Map operator/proxy lifecycle events onto existing AuditActionType values.
_EVENT_ACTION: dict[str, AuditActionType] = {
    "guardian_check": "event_received",
    "guardian_preview": "remediation_previewed",
    "guardian_blocked": "policy_evaluated",
    "guardian_apply": "action_executed",
    "proxy_fix_preview": "remediation_previewed",
    "proxy_fix_blocked": "policy_evaluated",
    "proxy_fix_applied": "action_executed",
    "prefer_direct_applied": "action_executed",
    "prefer_direct_blocked": "policy_evaluated",
    "ensure_proxy_health": "validation_completed",
}


def map_event_to_action(event: str) -> AuditActionType:
    """Map event to action.

    Args:
        event: event supplied by the caller.

    Returns:
        The computed `AuditActionType` value.

    Side effects:
        May read or write local platform records depending on inputs.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return _EVENT_ACTION.get(event, "event_received")


def _call_append_audit(
    action: AuditActionType,
    *,
    actor: str,
    payload: dict[str, Any],
    path: Path,
    write_tip: bool,
    event: str,
    subsystem: str,
) -> Any:
    """Append via domain event kernel (preferred) with AuditRecord-shaped return."""
    from src.platform_core.domain_events.writer import append_domain_event

    envelope = append_domain_event(
        event,
        source=subsystem or actor or "operator",
        payload=payload,
        actor=actor,
        action_type=action,
        path=path,
        write_tip=write_tip,
    )

    # Lightweight namespace matching AuditRecord attribute access used by callers.
    class _Record:
        pass

    rec = _Record()
    rec.audit_id = envelope.get("event_id")
    rec.action_type = action
    rec.current_hash = envelope.get("current_hash")
    rec.schema_version = envelope.get("schema_version")
    return rec


def append_custody_event(
    event: str,
    *,
    actor: str = "operator",
    subsystem: str = "proxy_drift",
    dry_run: bool | None = None,
    confirmation_supplied: bool = False,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    outcome: str | None = None,
    limitations: list[str] | None = None,
    extra: dict[str, Any] | None = None,
    path: Path | None = None,
    write_tip: bool = True,
    soft_fail: bool = True,
) -> dict[str, Any]:
    """Append one hash-chained custody row and refresh the tip anchor.

    Never stores confirmation token strings — only ``confirmation_supplied`` boolean.

    Soft-fail (default): write/call errors return ``{"ok": False, "error": ...}`` without raising.
    """
    action = map_event_to_action(event)
    target = path or default_canonical_path()
    payload: dict[str, Any] = {
        "subsystem": subsystem,
        "event": event,
        "confirmation_supplied": bool(confirmation_supplied),
    }
    if dry_run is not None:
        payload["dry_run"] = bool(dry_run)
    if before is not None:
        payload["before"] = before
    if after is not None:
        payload["after"] = after
    if outcome is not None:
        payload["outcome"] = outcome
    if limitations:
        payload["limitations"] = list(limitations)
    if extra:
        # Strip any accidental secret-like keys
        scrubbed = {
            k: v
            for k, v in extra.items()
            if k.lower() not in {"confirm", "confirmation", "confirm_phrase", "token", "password"}
        }
        payload["detail"] = scrubbed

    try:
        record = _call_append_audit(
            action,
            actor=actor,
            payload=payload,
            path=target,
            write_tip=write_tip,
            event=event,
            subsystem=subsystem,
        )
        return {
            "ok": True,
            "audit_id": getattr(record, "audit_id", None),
            "action_type": getattr(record, "action_type", action),
            "current_hash": getattr(record, "current_hash", None),
            "path": str(target),
        }
    except Exception as exc:
        if soft_fail:
            return {"ok": False, "error": str(exc), "path": str(target)}
        raise

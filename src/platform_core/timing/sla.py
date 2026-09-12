"""SLA and evidence-expiry helpers (deterministic, timezone-aware)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.platform_core.timing.models import Urgency

# Default SLA clocks (hours from detection) by urgency — configuration overrideable.
DEFAULT_SLA_HOURS: dict[Urgency, float] = {
    Urgency.LOW: 72.0,
    Urgency.MEDIUM: 24.0,
    Urgency.HIGH: 8.0,
    Urgency.CRITICAL: 2.0,
}

DEFAULT_EVIDENCE_TTL_HOURS: dict[Urgency, float] = {
    Urgency.LOW: 168.0,
    Urgency.MEDIUM: 48.0,
    Urgency.HIGH: 24.0,
    Urgency.CRITICAL: 12.0,
}


def sla_due_utc(detected: datetime, urgency: Urgency, *, hours: float | None = None) -> datetime:
    """Return sla due utc.

    Args:
        detected: detected supplied by the caller.
        urgency: urgency supplied by the caller.
        hours: hours supplied by the caller.

    Returns:
        The computed `datetime` value.

    Side effects:
        None.
    """
    h = hours if hours is not None else DEFAULT_SLA_HOURS[urgency]
    base = detected if detected.tzinfo else detected.replace(tzinfo=UTC)
    return base.astimezone(UTC) + timedelta(hours=h)


def evidence_expires_utc(detected: datetime, urgency: Urgency, *, hours: float | None = None) -> datetime:
    """Return evidence expires utc.

    Args:
        detected: detected supplied by the caller.
        urgency: urgency supplied by the caller.
        hours: hours supplied by the caller.

    Returns:
        The computed `datetime` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    h = hours if hours is not None else DEFAULT_EVIDENCE_TTL_HOURS[urgency]
    base = detected if detected.tzinfo else detected.replace(tzinfo=UTC)
    return base.astimezone(UTC) + timedelta(hours=h)


def format_utc(dt: datetime) -> str:
    """Format utc.

    Args:
        dt: dt supplied by the caller.

    Returns:
        The computed `str` value.

    Side effects:
        None.
    """
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

"""Timezone-aware maintenance and business-hours windows."""

from __future__ import annotations

from datetime import UTC, datetime, time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def resolve_tz(tz_name: str | None) -> ZoneInfo:
    """Resolve timezone; default UTC — never silently use a local region."""
    name = (tz_name or "UTC").strip() or "UTC"
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def parse_utc(iso: str) -> datetime:
    """Return parse utc.

    Args:
        iso: iso supplied by the caller.

    Returns:
        The computed `datetime` value.

    Side effects:
        None.
    """
    raw = iso.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def to_local(dt_utc: datetime, tz: ZoneInfo) -> datetime:
    """Return to local.

    Args:
        dt_utc: dt utc supplied by the caller.
        tz: tz supplied by the caller.

    Returns:
        The computed `datetime` value.

    Side effects:
        None.
    """
    return dt_utc.astimezone(tz)


def is_business_hours(
    dt_utc: datetime,
    *,
    tz: ZoneInfo,
    start: time = time(9, 0),
    end: time = time(18, 0),
    weekdays: frozenset[int] | None = None,
) -> bool:
    """Return True if local time falls in business hours (Mon–Fri by default)."""
    days = weekdays if weekdays is not None else frozenset({0, 1, 2, 3, 4})
    local = to_local(dt_utc, tz)
    if local.weekday() not in days:
        return False
    t = local.time()
    return start <= t < end


def in_named_window(
    dt_utc: datetime,
    *,
    tz: ZoneInfo,
    window_start_local: time,
    window_end_local: time,
    weekdays: frozenset[int] | None = None,
) -> bool:
    """Check inclusive start / exclusive end in local time."""
    return is_business_hours(
        dt_utc,
        tz=tz,
        start=window_start_local,
        end=window_end_local,
        weekdays=weekdays,
    )


def next_window_start_utc(
    dt_utc: datetime,
    *,
    tz: ZoneInfo,
    window_start_local: time = time(22, 0),
    weekdays: frozenset[int] | None = None,
) -> datetime:
    """Next occurrence of window start (local) as UTC — simple day-forward search."""
    days = weekdays if weekdays is not None else frozenset(range(7))
    local = to_local(dt_utc, tz)
    for offset in range(0, 8):
        candidate_date = local.date()
        if offset:
            from datetime import timedelta

            candidate_date = (local + timedelta(days=offset)).date()
        if candidate_date.weekday() not in days:
            continue
        candidate_local = datetime.combine(candidate_date, window_start_local, tzinfo=tz)
        candidate_utc = candidate_local.astimezone(UTC)
        if candidate_utc > dt_utc:
            return candidate_utc
    from datetime import timedelta

    fallback = local + timedelta(days=1)
    return datetime.combine(fallback.date(), window_start_local, tzinfo=tz).astimezone(UTC)

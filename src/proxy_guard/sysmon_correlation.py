"""Time-window helpers for correlating Sysmon rows with proxy-watch transitions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .attribution_model import AttributionEvidence


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        return None


def filter_sysmon_within_seconds_of_transition(
    events: list[AttributionEvidence],
    transition_timestamp: str | None,
    *,
    window_seconds: int = 10,
) -> list[AttributionEvidence]:
    """Keep Sysmon proof rows within ±*window_seconds* of a proxy-watch diff timestamp."""
    anchor = _parse_ts(transition_timestamp)
    if anchor is None:
        return events
    window = timedelta(seconds=max(1, window_seconds))
    kept: list[AttributionEvidence] = []
    for ev in events:
        if ev.source != "sysmon_event_13" or (ev.confidence_score or 0) < 0.85:
            kept.append(ev)
            continue
        observed = _parse_ts(ev.observed_at)
        if observed is None or abs(observed - anchor) <= window:
            kept.append(ev)
    return kept

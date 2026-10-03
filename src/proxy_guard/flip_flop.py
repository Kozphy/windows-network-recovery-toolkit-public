"""Detect repeated WinINET ``ProxyEnable`` toggles (ACTIVE_REVERTER suspicion).

Module responsibility:
    Scan normalized proxy-guard watch JSONL rows within a rolling time window and
    count enable/disable transitions for operator incident banners.

System placement:
    Consumed by :mod:`human_report` when formatting ``proxy-watch-report`` tails;
    read path only — never mutates registry.

Key invariants:
    * ``normalize_watch_record`` upgrades legacy v1 monitor rows without rewriting
      on-disk files.
    * Timestamps without timezone are treated as UTC.

Input assumptions:
    Records include ``before_snapshot`` / ``after_snapshot`` or legacy v1 enable
    fields; malformed timestamps are skipped silently.

Output guarantees:
    Incident summary dict with toggle count, window bounds, and recovery guidance
    strings suitable for stderr banners.

Failure modes:
    Empty or corrupt JSONL yields zero toggles — callers must not infer stability
    from absence alone.

Audit Notes:
    When toggle count exceeds threshold, recommend stopping suspected process trees
    before repeating ``proxy-disable`` — see ``docs/proxy_green_definition.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        return None


def normalize_watch_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Upgrade schema v1 monitor rows for shared analysis (read path only)."""

    if raw.get("event") == "proxy_state_change" or raw.get("schema_version") == 1:
        return {
            **raw,
            "schema_version": raw.get("schema_version", 1),
            "event": raw.get("event", "proxy_state_change"),
            "timestamp": raw.get("timestamp_utc") or raw.get("timestamp"),
            "before_snapshot": {
                "proxy_enable": raw.get("old_enable"),
                "proxy_server": raw.get("old_server_masked"),
            },
            "after_snapshot": {
                "proxy_enable": raw.get("new_enable"),
                "proxy_server": raw.get("new_server_masked"),
            },
        }
    return raw


def iter_enable_transitions(records: list[dict[str, Any]]) -> list[tuple[datetime, int, int]]:
    """Return (timestamp, before_enable, after_enable) for each row with a known toggle."""

    out: list[tuple[datetime, int, int]] = []
    for raw in records:
        rec = normalize_watch_record(raw)
        ts = _parse_ts(rec.get("timestamp") or rec.get("timestamp_utc"))
        if ts is None:
            continue
        before = rec.get("before_snapshot") or {}
        after = rec.get("after_snapshot") or {}
        try:
            old_en = int(before.get("proxy_enable"))
            new_en = int(after.get("proxy_enable"))
        except (TypeError, ValueError):
            continue
        if old_en != new_en:
            out.append((ts, old_en, new_en))
    return out


@dataclass(frozen=True)
class ActiveReverterResult:
    """Incident-style classification when enable flips repeat in a window."""

    incident_class: str
    toggle_count: int
    window_minutes: int
    first_seen_utc: str
    last_seen_utc: str

    def to_dict(self) -> dict[str, Any]:
        """To dict.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "incident_class": self.incident_class,
            "toggle_count": self.toggle_count,
            "window_minutes": self.window_minutes,
            "first_seen_utc": self.first_seen_utc,
            "last_seen_utc": self.last_seen_utc,
            "summary": (
                "ACTIVE_REVERTER suspected: ProxyEnable toggled repeatedly. "
                "Registry writer is not proven. Listener/process correlation is evidence only."
            ),
            "recommended_actions": [
                "Identify registry writer: WMI process command line, Procmon RegSetValue, or Sysmon EID 13.",
                "Do not reset proxy in a loop — stop the suspected process tree first.",
                "Run scripts\\reset_proxy.bat once, then python -m src proxy-disable --dry-run false "
                "--confirm DISABLE_WININET_PROXY --soak-minutes 15",
            ],
        }


def detect_active_reverter(
    records: list[dict[str, Any]],
    *,
    window_minutes: int = 30,
    min_toggles: int = 3,
    reference_utc: datetime | None = None,
) -> ActiveReverterResult | None:
    """Return ACTIVE_REVERTER when >= ``min_toggles`` enable transitions fall in the window."""

    transitions = iter_enable_transitions(records)
    if len(transitions) < min_toggles:
        return None
    if reference_utc is not None:
        ref = reference_utc
    elif transitions:
        ref = transitions[-1][0]
    else:
        ref = datetime.now(UTC)
    window = timedelta(minutes=window_minutes)
    cutoff = ref - window
    in_window = [t for t in transitions if t[0] >= cutoff]
    if len(in_window) < min_toggles:
        return None
    return ActiveReverterResult(
        incident_class="ACTIVE_REVERTER",
        toggle_count=len(in_window),
        window_minutes=window_minutes,
        first_seen_utc=in_window[0][0].isoformat(),
        last_seen_utc=in_window[-1][0].isoformat(),
    )

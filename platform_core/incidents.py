"""Deterministic incident clustering for portfolio-style KPIs derived from FailureEvent rows.

Module responsibility:
    Groups JSON-shaped failure events sharing category + heuristic signal fingerprints whenever
    their timestamps fall inside a configurable sliding window, emitting :class:`IncidentCluster`
    models consumed by ``platform_core.storage.list_metrics``.

System placement:
    Pure Python helper — invoked from storage aggregation and optional demos, not routers directly.

Input assumptions:
    Rows resemble ``FailureEvent.model_dump()`` output with scalar ``category`` /
    ``recommended_action_key`` fragments and RFC3339-ish ``*_seen_at`` fields (``Z`` suffix allowed).

Output guarantees:
    Deterministic ordering for fixed inputs; no filesystem or network touches.

Handling of malformed data:
    Events missing ``event_id`` skip clustering; timestamps that fail parsing default to ``now()``
    UTC for both endpoints—document this when interpreting synthetic fixtures.

Audit Notes:
    Cluster counts derive entirely from offline JSONL—if ingestion duplicates events, KPIs inflate
    symmetrically unless upstream deduplicates ``event_id`` values.

Engineering Notes:
    ``window_seconds`` defaults differ between call sites (`list_metrics` uses 7200s here)—keep those
    call sites documented when extending fleet semantics.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

ClusterSeverity = Literal["low", "medium", "high"]


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _severity_rank(s: str | None) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(str(s or "low").lower(), 1)


def _rank_to_label(r: int) -> ClusterSeverity:
    if r >= 3:
        return "high"
    if r == 2:
        return "medium"
    return "low"


class IncidentCluster(BaseModel):
    """Correlated failure events within a category/pattern/time window."""

    cluster_id: str = Field(description="Stable UUID for this cluster row.")
    category: str
    pattern_key: str = Field(description="category + fingerprint of signals / recommended action.")
    event_ids: list[str]
    endpoint_ids: list[str]
    first_seen_at: str
    last_seen_at: str
    cluster_severity: ClusterSeverity
    affected_endpoint_count: int = Field(ge=0)
    event_count: int = Field(ge=0)


def _pattern_fingerprint(ev: dict[str, Any]) -> str:
    cat = str(ev.get("category") or "unknown")
    action = str(ev.get("recommended_action_key") or "")
    summary_hint = str(ev.get("summary") or "")[:48]
    raw = f"{cat}|{action}|{summary_hint}"
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def _make_cluster(bucket: list[tuple[dict[str, Any], datetime, datetime]]) -> IncidentCluster:
    evs = [b[0] for b in bucket]
    first_t = min(b[1] for b in bucket)
    last_t = max(b[2] for b in bucket)
    cat = str(evs[0].get("category") or "unknown")
    fp = _pattern_fingerprint(evs[0])
    pattern_display = f"{cat}:{fp}"
    eids = sorted({str(e.get("event_id")) for e in evs if e.get("event_id")})
    eps = sorted({str(e.get("endpoint_id") or "") for e in evs if e.get("endpoint_id")})
    ranks = [_severity_rank(e.get("severity")) for e in evs]
    mx = max(ranks) if ranks else 1
    if len(eps) >= 2 and mx < 3:
        mx = min(3, mx + 1)
    sev = _rank_to_label(mx)
    cid = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            "|".join(eids + [first_t.isoformat(), last_t.isoformat()]),
        )
    )
    return IncidentCluster(
        cluster_id=cid,
        category=cat,
        pattern_key=pattern_display,
        event_ids=eids,
        endpoint_ids=eps,
        first_seen_at=first_t.replace(tzinfo=UTC).isoformat(),
        last_seen_at=last_t.replace(tzinfo=UTC).isoformat(),
        cluster_severity=sev,
        affected_endpoint_count=len(eps),
        event_count=len(evs),
    )


def cluster_failure_events(
    events: list[dict[str, Any]],
    *,
    window_seconds: int = 3600,
) -> list[IncidentCluster]:
    """Slice failure timelines into deterministic incident clusters without mutating inputs.

    Args:
        events: Failure event dicts sourced from append-only JSONL reads.
        window_seconds: Maximum gap between consecutive timestamps inside a fingerprint bucket
            before spawning a fresh cluster row.

    Returns:
        Sorted :class:`IncidentCluster` summaries ready for KPI serialization.

    Raises:
        ValueError is not emitted; malformed timestamps degrade to clustered ``utcnow()`` pairs.

    Side effects:
        None.

    Idempotency:
        Re-running with the same ordered ``events`` yields bit-identical output.
    """
    groups: dict[str, list[tuple[dict[str, Any], datetime, datetime]]] = defaultdict(list)

    for ev in events:
        eid = str(ev.get("event_id") or "")
        if not eid:
            continue
        fs = _parse_iso(ev.get("first_seen_at")) or _parse_iso(ev.get("last_seen_at"))
        ls = _parse_iso(ev.get("last_seen_at")) or fs
        if fs is None or ls is None:
            now = datetime.now(UTC)
            fs = ls = now
        cat = str(ev.get("category") or "unknown")
        fp = _pattern_fingerprint(ev)
        gkey = f"{cat}|{fp}"
        groups[gkey].append((ev, fs, ls))

    out: list[IncidentCluster] = []
    for gkey in sorted(groups.keys()):
        rows = sorted(groups[gkey], key=lambda x: (x[2], str(x[0].get("event_id"))))
        bucket: list[tuple[dict[str, Any], datetime, datetime]] = []
        for row in rows:
            ev, fs, ls = row
            if not bucket:
                bucket.append(row)
                continue
            prev_ls = max(b[2] for b in bucket)
            if (ls - prev_ls).total_seconds() > window_seconds:
                out.append(_make_cluster(bucket))
                bucket = [row]
            else:
                bucket.append(row)
        if bucket:
            out.append(_make_cluster(bucket))

    out.sort(key=lambda c: (c.last_seen_at, c.cluster_id))
    return out


def incident_summaries(
    events: list[dict[str, Any]],
    *,
    window_seconds: int = 7200,
) -> list[dict[str, Any]]:
    """Serialize :class:`IncidentCluster` rows to plain dicts for HTTP responses."""

    return [c.model_dump() for c in cluster_failure_events(events, window_seconds=window_seconds)]

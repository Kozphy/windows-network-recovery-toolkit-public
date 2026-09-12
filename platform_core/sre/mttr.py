"""MTTR/MTTD metrics from incident lifecycle events — not fixture estimates."""

from __future__ import annotations

from datetime import UTC, datetime

from .event_store import DomainEventStore
from .models import IncidentPhase, MTTRMetrics
from .projector import list_incident_ids, rebuild_incident


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    text = ts.replace("Z", "+00:00") if ts.endswith("Z") else ts
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _delta_seconds(start: str | None, end: str | None) -> float | None:
    a, b = _parse_iso(start), _parse_iso(end)
    if not a or not b:
        return None
    if a.tzinfo is None:
        a = a.replace(tzinfo=UTC)
    if b.tzinfo is None:
        b = b.replace(tzinfo=UTC)
    return max(0.0, (b - a).total_seconds())


def _percentile(values: list[float], p: float) -> float | None:
    if not values:
        return None
    sorted_v = sorted(values)
    idx = int(round((p / 100.0) * (len(sorted_v) - 1)))
    return round(sorted_v[idx], 2)


def compute_incident_mttr_metrics(*, store: DomainEventStore | None = None) -> MTTRMetrics:
    """Derive SRE reliability metrics from event-sourced incident projections."""
    st = store or DomainEventStore()
    incident_ids = list_incident_ids(store=st)

    mttd_list: list[float] = []
    mtti_list: list[float] = []
    mttr_list: list[float] = []
    resolved = 0
    false_positives = 0
    investigations = 0

    for iid in incident_ids:
        proj = rebuild_incident(iid, store=st)
        if proj.phase == IncidentPhase.FALSE_POSITIVE:
            false_positives += 1
            continue
        if proj.investigation_started_at:
            investigations += 1

        # MTTD: detected → acknowledged (or investigation if no ack)
        mttd = _delta_seconds(proj.detected_at, proj.acknowledged_at or proj.investigation_started_at)
        if mttd is not None:
            mttd_list.append(mttd)

        # MTTI: detected → root cause identified
        mtti = _delta_seconds(proj.detected_at, proj.root_cause_identified_at)
        if mtti is not None:
            mtti_list.append(mtti)

        # MTTR: detected → resolved
        if proj.phase == IncidentPhase.RESOLVED and proj.resolved_at:
            mttr = _delta_seconds(proj.detected_at, proj.resolved_at)
            if mttr is not None:
                mttr_list.append(mttr)
                resolved += 1

    total = len(incident_ids)
    fp_rate = (false_positives / total) if total else None

    return MTTRMetrics(
        incident_count=total,
        resolved_count=resolved,
        mean_time_to_detect_seconds=round(sum(mttd_list) / len(mttd_list), 2) if mttd_list else None,
        mean_time_to_identify_seconds=round(sum(mtti_list) / len(mtti_list), 2) if mtti_list else None,
        mean_time_to_recover_seconds=round(sum(mttr_list) / len(mttr_list), 2) if mttr_list else None,
        p50_mttr_seconds=_percentile(mttr_list, 50),
        p95_mttr_seconds=_percentile(mttr_list, 95),
        false_positive_rate=round(fp_rate, 4) if fp_rate is not None else None,
        investigation_count=investigations,
    )


def mttr_metrics_for_prometheus(metrics: MTTRMetrics) -> dict[str, float]:
    """Map to Prometheus gauge names — explicit, no hidden conversion."""
    out: dict[str, float] = {
        "platform_sre_incident_count": float(metrics.incident_count),
        "platform_sre_incident_resolved_count": float(metrics.resolved_count),
        "platform_sre_investigation_count": float(metrics.investigation_count),
    }
    if metrics.mean_time_to_detect_seconds is not None:
        out["platform_sre_mttd_seconds"] = metrics.mean_time_to_detect_seconds
    if metrics.mean_time_to_identify_seconds is not None:
        out["platform_sre_mtti_seconds"] = metrics.mean_time_to_identify_seconds
    if metrics.mean_time_to_recover_seconds is not None:
        out["platform_sre_mttr_seconds"] = metrics.mean_time_to_recover_seconds
    if metrics.p50_mttr_seconds is not None:
        out["platform_sre_mttr_p50_seconds"] = metrics.p50_mttr_seconds
    if metrics.p95_mttr_seconds is not None:
        out["platform_sre_mttr_p95_seconds"] = metrics.p95_mttr_seconds
    if metrics.false_positive_rate is not None:
        out["platform_sre_false_positive_rate"] = metrics.false_positive_rate
    return out

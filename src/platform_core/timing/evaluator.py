"""Deterministic timing evaluator — does not authorize execution."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, time
from typing import Any

from src.platform_core.timing.models import (
    TimingContext,
    TimingDecision,
    TimingReasonCode,
    Urgency,
)
from src.platform_core.timing.sla import evidence_expires_utc, format_utc, sla_due_utc
from src.platform_core.timing.windows import (
    is_business_hours,
    next_window_start_utc,
    parse_utc,
    resolve_tz,
)


def _fingerprint(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def _urgency_from(
    *,
    classification: str,
    policy_outcome: str,
    explicit: str | None,
) -> Urgency:
    if explicit:
        try:
            return Urgency(str(explicit).lower())
        except ValueError:
            pass
    cls = str(classification).upper()
    if cls in {"POSSIBLE_MITM_RISK", "UNKNOWN_LOCAL_PROXY"}:
        return Urgency.HIGH
    if cls in {"DEAD_PROXY_CONFIG"}:
        return Urgency.HIGH
    if str(policy_outcome).upper() in {"BLOCK", "BLOCK_DESTRUCTIVE"}:
        return Urgency.MEDIUM
    return Urgency.MEDIUM


class TimingEvaluator:
    """Represent the timing evaluator type.

    Side effects:
        None.
    """

    def evaluate(
        self,
        *,
        case_id: str = "",
        detected_at_utc: str,
        evaluated_at_utc: str | None = None,
        timezone_name: str | None = None,
        classification: str = "",
        policy_outcome: str = "",
        urgency: str | None = None,
        maintenance_window_required: bool = False,
        change_freeze_active: bool = False,
        retry_after_utc: str | None = None,
        sla_hours: float | None = None,
        evidence_ttl_hours: float | None = None,
        business_hours_start: time = time(9, 0),
        business_hours_end: time = time(18, 0),
        maintenance_start: time = time(22, 0),
        maintenance_end: time = time(5, 0),
        config: dict[str, Any] | None = None,
    ) -> TimingContext:
        """Evaluate the requested value.

        Args:
            case_id: case id supplied by the caller.
            detected_at_utc: detected at utc supplied by the caller.
            evaluated_at_utc: evaluated at utc supplied by the caller.
            timezone_name: timezone name supplied by the caller.
            classification: classification supplied by the caller.
            policy_outcome: policy outcome supplied by the caller.
            urgency: urgency supplied by the caller.
            maintenance_window_required: maintenance window required supplied by the caller.
            change_freeze_active: change freeze active supplied by the caller.
            retry_after_utc: retry after utc supplied by the caller.
            sla_hours: sla hours supplied by the caller.
            evidence_ttl_hours: evidence ttl hours supplied by the caller.
            business_hours_start: business hours start supplied by the caller.
            business_hours_end: business hours end supplied by the caller.
            maintenance_start: maintenance start supplied by the caller.
            maintenance_end: maintenance end supplied by the caller.
            config: config supplied by the caller.

        Returns:
            The computed `TimingContext` value.

        Side effects:
            None.
        """
        cfg = dict(config or {})
        tz_name = timezone_name or cfg.get("timezone") or "UTC"
        tz = resolve_tz(str(tz_name))
        detected = parse_utc(detected_at_utc)
        now = parse_utc(evaluated_at_utc) if evaluated_at_utc else datetime.now(UTC)
        urg = _urgency_from(
            classification=classification,
            policy_outcome=policy_outcome,
            explicit=urgency or cfg.get("urgency"),
        )
        if "maintenance_window_required" in cfg:
            maintenance_window_required = bool(cfg["maintenance_window_required"])
        if "change_freeze_active" in cfg:
            change_freeze_active = bool(cfg["change_freeze_active"])

        sla_due = sla_due_utc(detected, urg, hours=sla_hours)
        evidence_exp = evidence_expires_utc(detected, urg, hours=evidence_ttl_hours)
        biz = is_business_hours(
            now,
            tz=tz,
            start=business_hours_start,
            end=business_hours_end,
        )

        in_maint: bool | None = None
        action_start = action_end = None
        if maintenance_window_required:
            # Night window may wrap midnight — treat as local start..23:59 or 00:00..end.
            from src.platform_core.timing.windows import to_local

            local = to_local(now, tz)
            t = local.time()
            if maintenance_start <= maintenance_end:
                in_maint = maintenance_start <= t < maintenance_end
            else:
                in_maint = t >= maintenance_start or t < maintenance_end
            if not in_maint:
                action_start = format_utc(
                    next_window_start_utc(now, tz=tz, window_start_local=maintenance_start)
                )

        reasons: list[TimingReasonCode] = []
        decision = TimingDecision.READY

        if now >= evidence_exp:
            decision = TimingDecision.EVIDENCE_EXPIRED
            reasons.append(TimingReasonCode.EVIDENCE_STALE)
        else:
            reasons.append(TimingReasonCode.EVIDENCE_VALID)

        if now >= sla_due and decision != TimingDecision.EVIDENCE_EXPIRED:
            decision = TimingDecision.SLA_OVERDUE
            reasons.append(TimingReasonCode.SLA_BREACHED)
        elif decision not in {TimingDecision.EVIDENCE_EXPIRED}:
            reasons.append(TimingReasonCode.WITHIN_SLA)

        if change_freeze_active and decision in {
            TimingDecision.READY,
            TimingDecision.DEFERRED_TO_WINDOW,
            TimingDecision.MONITOR_UNTIL,
        }:
            # Freeze defers execution but must not suppress urgent escalation.
            if urg in {Urgency.HIGH, Urgency.CRITICAL}:
                decision = TimingDecision.ESCALATE_NOW
                reasons.append(TimingReasonCode.HIGH_URGENCY_ESCALATION)
                reasons.append(TimingReasonCode.CHANGE_FREEZE_ACTIVE)
            else:
                decision = TimingDecision.BLOCKED_BY_CHANGE_FREEZE
                reasons.append(TimingReasonCode.CHANGE_FREEZE_ACTIVE)

        if (
            maintenance_window_required
            and in_maint is False
            and decision
            in {
                TimingDecision.READY,
                TimingDecision.MONITOR_UNTIL,
            }
        ):
            decision = TimingDecision.DEFERRED_TO_WINDOW
            reasons.append(TimingReasonCode.OUTSIDE_MAINTENANCE_WINDOW)
        elif maintenance_window_required and in_maint:
            reasons.append(TimingReasonCode.IN_MAINTENANCE_WINDOW)

        if urg in {Urgency.HIGH, Urgency.CRITICAL} and decision == TimingDecision.READY:
            # High urgency after hours escalates communication — never execution.
            if not biz:
                decision = TimingDecision.ESCALATE_NOW
                reasons.append(TimingReasonCode.HIGH_URGENCY_ESCALATION)
                reasons.append(TimingReasonCode.AFTER_HOURS)
            else:
                reasons.append(TimingReasonCode.BUSINESS_HOURS)
                reasons.append(TimingReasonCode.HIGH_URGENCY_ESCALATION)
                # Still escalate-now for critical during business hours (communication).
                if urg == Urgency.CRITICAL:
                    decision = TimingDecision.ESCALATE_NOW

        if retry_after_utc:
            reasons.append(TimingReasonCode.RETRY_AFTER_SET)
            try:
                ra = parse_utc(retry_after_utc)
                if now < ra and decision == TimingDecision.READY:
                    decision = TimingDecision.MONITOR_UNTIL
            except ValueError:
                pass

        if biz is True:
            if (
                TimingReasonCode.BUSINESS_HOURS not in reasons
                and TimingReasonCode.AFTER_HOURS not in reasons
            ):
                reasons.append(TimingReasonCode.BUSINESS_HOURS)
        elif biz is False and TimingReasonCode.AFTER_HOURS not in reasons:
            reasons.append(TimingReasonCode.AFTER_HOURS)

        fp = _fingerprint(
            {
                "case_id": case_id,
                "detected_at_utc": format_utc(detected),
                "evaluated_at_utc": format_utc(now),
                "timezone": str(tz),
                "urgency": urg.value,
                "classification": classification,
                "maintenance_window_required": maintenance_window_required,
                "change_freeze_active": change_freeze_active,
                "retry_after_utc": retry_after_utc,
            }
        )

        return TimingContext(
            case_id=case_id,
            detected_at_utc=format_utc(detected),
            evaluated_at_utc=format_utc(now),
            timezone=str(tz),
            clock_source="UTC",
            urgency=urg,
            action_window_start_utc=action_start,
            action_window_end_utc=action_end,
            sla_due_utc=format_utc(sla_due),
            evidence_expires_utc=format_utc(evidence_exp),
            retry_after_utc=retry_after_utc,
            maintenance_window_required=maintenance_window_required,
            in_maintenance_window=in_maint,
            change_freeze_active=change_freeze_active,
            business_hours=biz,
            decision=decision,
            reason_codes=tuple(dict.fromkeys(reasons)),
            inputs_fingerprint=fp,
            config_refs={"timezone_requested": tz_name},
        )


def evaluate_timing(**kwargs: Any) -> TimingContext:
    """Evaluate timing.

    Args:
        **kwargs: kwargs supplied by the caller.

    Returns:
        The computed `TimingContext` value.

    Side effects:
        None.
    """
    return TimingEvaluator().evaluate(**kwargs)

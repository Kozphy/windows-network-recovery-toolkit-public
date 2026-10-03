"""Proxy Guard polling loop: detect HKCU drift, attribute, decide, optional rollback.

Module responsibility:
    Poll WinINET registry, diff snapshots, merge layered attribution, evaluate policy,
    emit human-readable stderr banners, and append unified audit JSONL rows.

System placement:
    Entry via :mod:`service` / ``python -m src proxy-guard``; complements read-only
    :mod:`watcher` and remediation flows in :mod:`remediation`.

Key invariants:
    * Default posture is observe/preview — live rollback requires explicit policy +
      confirmation paths documented in :mod:`rollback`.
    * Listener correlation is never labeled registry-writer proof.

Input assumptions:
    Windows host with readable HKCU Internet Settings; ``subprocess.run`` injectable
    for tests.

Side effects:
    Appends audit files under ``logs/`` and ``reports/``; may invoke rollback
    primitives when policy + CLI flags allow (HKCU WinINET only).

Failure modes:
    Transient ``reg`` read failures are retried via :mod:`probes`; attribution
    degrades to ``unknown`` when optional telemetry is absent.

Audit Notes:
    Correlate ``registry_change_detected`` rows with ``repair_audit.jsonl`` when
    operators also run ``proxy-disable``; flip-flop banners originate in
    :mod:`flip_flop`.
"""

from __future__ import annotations

import copy
import json
import sys
import time
from pathlib import Path
from typing import Any, Literal, cast

from ..core.jsonl import append_jsonl
from .attribution import (
    enhance_attribution_for_pipeline,
    heuristic_attribution_to_audit_dict,
)
from .attribution_engine import (
    attribute_proxy_change as registry_layer_attribute_proxy_change,
)
from .attribution_engine import (
    layered_to_heuristic_pipeline,
)
from .audit import build_rollback_plan, emit_pipeline_audit_v1, emit_proxy_guard_audit
from .config import ProxyGuardServiceConfig
from .connectivity import capture_connectivity_snapshot, compare_connectivity
from .decision import finalize_decision
from .diff import (
    proxy_state_audit_dict,
    verify_hkcu_core_matches_prior,
    wininet_argv_restored_fields,
)
from .events import proxy_guard_control_event
from .evidence import build_connectivity_evidence, build_registry_change_evidence
from .guard_evaluation import evaluate_proxy_transition
from .human_report import format_proxy_guard_change
from .models import (
    AttributionResult,
    HeuristicPipelineAttribution,
    ProxyGuardAuditRecord,
    ProxySnapshot,
    RollbackPlan,
    RollbackResult,
)
from .owner import attribution_payload
from .parser import parse_proxy_server
from .pipeline import policy_payload_for_audit, rollback_payload_for_audit, summarize_stdout_event
from .planning import listen_port_for_attribution, normalize_registry_view, registry_views_equal
from .port_listen_probe import localhost_port_listen_state
from .probes import read_proxy_registry_with_retries
from .process_attribution import resolve_attribution
from .proxy_path_operational import assess_proxy_path_operational
from .rollback import execute_known_good_proxy_restore, execute_lkg_snapshot_rollback
from .rollback_limits import RollbackLimiter
from .snapshot_capture import capture_proxy_snapshot, load_lkg_snapshot, save_lkg_snapshot
from .structured_log import emit_structured_log

_LOGGER = "proxy_guard.guard"


def resolved_repo_root(explicit: Path | None, jsonl_path: Path) -> Path:
    """Resolved repo root.

    Args:
        explicit: The explicit value supplied by the caller.
        jsonl_path: Filesystem path used by the operation.

    Returns:
        The Path result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if explicit is not None:
        return explicit.resolve()
    if jsonl_path.parent.name.lower() == "logs":
        return jsonl_path.parent.parent.resolve()
    return jsonl_path.parent.resolve()


def _safe_listen_attribution(
    port: int | None,
    *,
    run: Any,
    structured_log_path: Any,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    if port is None:
        return (
            {
                "port": None,
                "owners": [],
                "notes": ["no_listen_port_for_attribution"],
            },
            (),
        )
    try:
        return attribution_payload(int(port), run=run), ()
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        emit_structured_log(
            logger=_LOGGER,
            level="WARNING",
            event="attribution_subprocess_failed",
            file_path=structured_log_path,
            extra={"error": str(exc), "port": port},
        )
        return (
            {"port": port, "owners": [], "notes": ["attribution_failure", str(exc)]},
            ("attribution_failure",),
        )


def winhttp_explicit(lkg: ProxySnapshot | None) -> bool:
    """Winhttp explicit.

    Args:
        lkg: The lkg value supplied by the caller.

    Returns:
        The bool result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if not lkg:
        return False
    if (lkg.winhttp_proxy_server_literal or "").strip():
        return True
    if lkg.winhttp_direct_access:
        return True
    return bool((lkg.winhttp_proxy or "").strip())


def run_proxy_guard_guard_loop(cfg: ProxyGuardServiceConfig) -> None:
    """Polling loop with LKG restores, attribution, rollback safety, consolidated audit JSONL."""
    repo_root = resolved_repo_root(cfg.repo_root, cfg.jsonl_path)
    repo_root.mkdir(parents=True, exist_ok=True)
    reports_dir = repo_root / "reports"
    logs_dir = repo_root / "logs"
    reports_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    lkg_path = reports_dir / "proxy_guard_lkg.json"
    effective_rollback = cfg.auto_rollback or cfg.cli_rollback
    confirm_required = cfg.cli_rollback and not cfg.auto_rollback
    phrase_ok = cfg.rollback_confirm_phrase.strip() == "RESTORE_PROXY"
    live_rollback_gate = bool(
        effective_rollback and not cfg.dry_run_rollback and (not confirm_required or phrase_ok),
    )

    limiter = RollbackLimiter(cfg.rollback_limits)
    prior_registry_view: dict[str, Any] | None = None
    prior_full_snap: ProxySnapshot | None = None
    prior_connectivity = None
    registry_change_events = 0

    emit_structured_log(
        logger=_LOGGER,
        level="INFO",
        event="proxy_guard_startup",
        file_path=cfg.structured_log_path,
        extra={"repo_root": str(repo_root)},
    )

    while True:
        t0 = time.perf_counter()
        snap, probe_notes = read_proxy_registry_with_retries(run=cfg.run, settings=cfg.probe)
        full_snap_curr = capture_proxy_snapshot(
            run=cfg.run,
            registry_snapshot=snap,
            query_timeout=cfg.probe.timeout_seconds,
        )
        if cfg.trust_current_lkg and prior_registry_view is None:
            save_lkg_snapshot(lkg_path, full_snap_curr)

        lkg = load_lkg_snapshot(lkg_path)
        parsed = parse_proxy_server(snap.proxy_server)
        reg_dict = snap.to_dict()
        view = normalize_registry_view(reg_dict, parsed.to_dict())

        duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        emit_structured_log(
            logger=_LOGGER,
            level="INFO" if not probe_notes else "WARNING",
            event="registry_probe_complete",
            file_path=cfg.structured_log_path,
            extra={"duration_ms": duration_ms, "proxy_enable": snap.proxy_enable},
        )

        if prior_registry_view is None:
            ev = proxy_guard_control_event(
                event_type="initial",
                previous_registry_view={},
                current_registry_view=copy.deepcopy(view),
                attribution={"port": None, "owners": [], "notes": ["initial_snapshot"]},
                policy_source=str(cfg.policy.source_path),
                decision="informational",
                decision_detail="baseline_before_monitoring",
                action="none",
                matched_rule=None,
                primary_process_name=None,
                rollback_detail=None,
                post_rollback_registry_view=None,
                probe_notes=probe_notes if probe_notes else None,
                rollback_suppressed_reason=None,
            )
            append_jsonl(cfg.jsonl_path, ev)
            print(json.dumps(view, indent=2, ensure_ascii=False))
            prior_registry_view = view
            prior_full_snap = full_snap_curr
            prior_connectivity = capture_connectivity_snapshot(
                run=cfg.run,
                snapshot=full_snap_curr,
                timeout_seconds=cfg.probe.timeout_seconds,
            )
            if cfg.once:
                return
            time.sleep(cfg.interval_seconds)
            continue

        if registry_views_equal(prior_registry_view, view):
            prior_full_snap = full_snap_curr
            prior_connectivity = capture_connectivity_snapshot(
                run=cfg.run,
                snapshot=full_snap_curr,
                timeout_seconds=cfg.probe.timeout_seconds,
            )
            if cfg.once:
                return
            time.sleep(cfg.interval_seconds)
            continue

        print("[proxy-guard] registry change detected", file=sys.stderr)
        prev_view = copy.deepcopy(prior_registry_view)
        curr_view = copy.deepcopy(view)
        try:
            win = int(max(60, min(600, getattr(cfg, "attribution_since_seconds", 90))))
            layered = registry_layer_attribute_proxy_change(
                prev_view,
                curr_view,
                since_seconds=win,
                evidence_csv=getattr(cfg, "evidence_csv", None),
                run=cfg.run,
            )
            heuristic_pipeline = layered_to_heuristic_pipeline(layered)
        except Exception as exc:
            heuristic_pipeline = HeuristicPipelineAttribution(
                candidate_actor=None,
                attribution_confidence="unknown",
                attribution_method="unavailable",
                attribution_notes=(
                    "best-effort attribution only",
                    "registry polling cannot prove exact writer process",
                    f"layered_attribution_failed:{type(exc).__name__}",
                ),
            )

        emit_structured_log(
            logger=_LOGGER,
            level="INFO",
            event="registry_change_detected",
            file_path=cfg.structured_log_path,
            extra={"attribute": heuristic_pipeline.to_jsonable()},
        )

        parsed_prev = parse_proxy_server(prev_view.get("proxy_server"))
        parsed_after = parsed
        prev_snap_guard = prior_full_snap or capture_proxy_snapshot(
            registry_snapshot=snap,
            run=cfg.run,
            query_timeout=cfg.probe.timeout_seconds,
        )
        curr_snap_guard = full_snap_curr

        port = listen_port_for_attribution(parsed_after)
        owners_payload = {"port": port, "owners": [], "notes": list(probe_notes)}
        if parsed_after.is_localhost_proxy and port is not None:
            listen_rows, lst_notes = _safe_listen_attribution(
                port,
                run=cfg.run,
                structured_log_path=cfg.structured_log_path,
            )
            owners_payload = listen_rows
            attr_notes = tuple(lst_notes) + tuple(probe_notes)
        else:
            attr_notes = tuple(probe_notes)

        attrib: AttributionResult = resolve_attribution(
            mode=cfg.attribution_mode,
            owners_payload=owners_payload,
            run=cfg.run,
        )
        attrib, heuristic_supplement = enhance_attribution_for_pipeline(
            base=attrib,
            owners_payload=owners_payload,
            run=cfg.run,
        )

        port_listen = localhost_port_listen_state(port, run=cfg.run)

        path_assessment = assess_proxy_path_operational(
            proxy_enable=curr_snap_guard.proxy_enable,
            proxy_server=curr_snap_guard.proxy_server,
            auto_config_url=curr_snap_guard.auto_config_url,
            parsed=parsed_after,
            port_listen=port_listen,
            run=cfg.run,
            include_https_contrast=True,
            timeout_seconds=cfg.probe.timeout_seconds,
        )

        gd = evaluate_proxy_transition(
            prior_snap=prev_snap_guard,
            curr_snap=curr_snap_guard,
            parsed_prior=parsed_prev,
            parsed_after=parsed_after,
            attribution=attrib,
            policy=cfg.policy,
            port_listen=port_listen,
            path_assessment=path_assessment,
        )
        post_connectivity = capture_connectivity_snapshot(
            run=cfg.run,
            snapshot=curr_snap_guard,
            timeout_seconds=cfg.probe.timeout_seconds,
        )
        validation = compare_connectivity(
            pre_change=prior_connectivity, post_change=post_connectivity
        )
        final_decision = finalize_decision(
            policy_decision=gd,
            connectivity_validation=validation,
            attribution=attrib,
            parsed_is_localhost=parsed_after.is_localhost_proxy,
        )

        restore_basis = cfg.known_good_snapshot
        if restore_basis is None:
            restore_basis = lkg if lkg is not None else prev_snap_guard
        explicit_wh = winhttp_explicit(restore_basis)
        snapshot_restorable = prev_snap_guard is not None
        rb_plan_obj: RollbackPlan = build_rollback_plan(
            decision=gd.decision,
            rollback_allowed=gd.rollback_allowed,
            lkg_present=snapshot_restorable,
            auto_rollback_enabled=effective_rollback,
            live_rollback_enabled=live_rollback_gate,
            explicit_winhttp_data=explicit_wh,
            restore_git_npm_env=cfg.restore_git_npm_env,
        )

        action = "none"
        rollback_detail: dict[str, Any] | None = None
        post_rb_view: dict[str, Any] | None = None
        suppressed_reason: str | None = None
        rb_exec: dict[str, Any] | None = None
        rollback_verification = "not_run"
        rb_error: str | None = None
        restored_field_names: list[str] = []
        pipeline_rb_action = "rollback_skipped"

        if gd.decision == "blocked" and gd.rollback_allowed and effective_rollback:
            ok, reason = limiter.evaluate()
            if not ok:
                action = "suppressed"
                suppressed_reason = reason
                rb_exec = None
                pipeline_rb_action = "rollback_skipped"
                rb_error = reason
                emit_structured_log(
                    logger=_LOGGER,
                    level="WARNING",
                    event="rollback_suppressed",
                    file_path=cfg.structured_log_path,
                    extra={"reason": reason},
                )
                prior_registry_view = curr_view
                prior_full_snap = curr_snap_guard
            else:
                action = "rollback"
                restore_target = cfg.known_good_snapshot
                if restore_target is None:
                    restore_target = prev_snap_guard
                if cfg.known_good_snapshot is not None:
                    rb_exec = execute_known_good_proxy_restore(
                        restore_target,
                        dry_run=not live_rollback_gate,
                        restore_winhttp=rb_plan_obj.restore_winhttp,
                        run=cfg.run,
                    )
                else:
                    rb_exec = execute_lkg_snapshot_rollback(
                        restore_target,
                        dry_run=not live_rollback_gate,
                        restore_winhttp=rb_plan_obj.restore_winhttp,
                        run=cfg.run,
                        restore_git_npm_env=cfg.restore_git_npm_env,
                    )
                rollback_detail = rb_exec
                wininet_rows = rb_exec.get("wininet_reg") or []
                if isinstance(wininet_rows, list):
                    restored_field_names = wininet_argv_restored_fields(wininet_rows)
                if live_rollback_gate and not rb_exec.get("skipped"):
                    limiter.record_rollback()
                snap_after, probe_after = read_proxy_registry_with_retries(
                    run=cfg.run, settings=cfg.probe
                )
                if probe_after:
                    emit_structured_log(
                        logger=_LOGGER,
                        level="WARNING",
                        event="registry_post_rollback_probe_notes",
                        file_path=cfg.structured_log_path,
                        extra={"notes": list(probe_after)},
                    )
                reg_after = snap_after.to_dict()
                parsed_a2 = parse_proxy_server(snap_after.proxy_server)
                post_rb_view = normalize_registry_view(reg_after, parsed_a2.to_dict())
                prior_registry_view = post_rb_view
                prior_full_snap = capture_proxy_snapshot(run=cfg.run, registry_snapshot=snap_after)

                if rb_exec.get("skipped"):
                    pipeline_rb_action = "rollback_skipped"
                elif not live_rollback_gate:
                    pipeline_rb_action = "rollback_preview"
                    rollback_verification = "not_run"
                elif rb_exec.get("success") is False:
                    pipeline_rb_action = "rollback_failed"
                    rb_error = "registry_or_netsh_nonzero"
                    rollback_verification = "failed"
                elif verify_hkcu_core_matches_prior(snap_after, prior_target=restore_target):
                    pipeline_rb_action = "rollback_applied"
                    rollback_verification = "passed"
                else:
                    pipeline_rb_action = "rollback_failed"
                    rb_error = "post_rollback_registry_mismatch"
                    rollback_verification = "failed"
        else:
            prior_registry_view = curr_view
            prior_full_snap = curr_snap_guard
            if gd.decision == "blocked" and gd.rollback_allowed and not effective_rollback:
                # Informational preview: policy would roll back if --auto-rollback/--rollback were enabled.
                pipeline_rb_action = "rollback_preview"

        if suppressed_reason is not None:
            rb_res = RollbackResult(status="skipped_suppressed", detail=suppressed_reason)
        elif gd.decision == "observe":
            rb_res = RollbackResult(
                status="skipped_observe", detail="no_registry_core_change_policy_branch"
            )
        elif gd.decision != "blocked":
            rb_res = RollbackResult(status="skipped_not_blocked", detail=gd.reason)
        elif not gd.rollback_allowed:
            rb_res = RollbackResult(status="skipped_roll_back_disallowed", detail=gd.reason)
        elif not effective_rollback:
            rb_res = RollbackResult(
                status="skipped_auto_rollback_disabled", detail="rollback_flags_disabled"
            )
        elif rb_exec is None:
            rb_res = RollbackResult(
                status="error", detail="rollback_executor_not_invoked_internal_error"
            )
        elif rb_exec.get("skipped"):
            reason = str(rb_exec.get("reason") or "")
            if reason == "skipped_no_lkg":
                rb_res = RollbackResult(status="skipped_no_lkg", detail=reason)
            elif "restore_git" in reason.lower():
                rb_res = RollbackResult(status="error", detail=reason)
            else:
                rb_res = RollbackResult(status="error", detail=reason or "skipped")
        elif not live_rollback_gate:
            rb_res = RollbackResult(
                status="skipped_dry_run",
                detail="dry_run_only",
                wininet_audit=tuple(rb_exec.get("wininet_reg") or ()),
                winhttp_audit=rb_exec.get("winhttp_restore"),
            )
        else:
            wins = tuple(rb_exec.get("wininet_reg") or ())
            partial = rb_exec.get("success") is False
            rb_res = RollbackResult(
                status="executed_partial" if partial else "executed_ok",
                detail="prior_snapshot_restore",
                wininet_audit=wins,
                winhttp_audit=rb_exec.get("winhttp_restore"),
            )

        rollback_audit_payload = rollback_payload_for_audit(
            action=pipeline_rb_action,
            restored_fields=restored_field_names,
            verification=cast(
                Literal["passed", "failed", "not_run"],
                rollback_verification,
            ),
            error=rb_error,
        )
        final_decision["rollback"] = {
            "action": rollback_audit_payload["action"],
            "restored_fields": rollback_audit_payload["restored_fields"],
            "requires_confirmation": bool(cfg.cli_rollback and not cfg.auto_rollback),
            "verification": rollback_audit_payload["verification"],
            "error": rollback_audit_payload["error"],
        }
        evidence_rows = [
            build_registry_change_evidence(
                observed_at=full_snap_curr.captured_at,
                value_name="ProxyEnable",
                old_value=prev_snap_guard.proxy_enable,
                new_value=curr_snap_guard.proxy_enable,
            ).to_jsonable(),
            build_registry_change_evidence(
                observed_at=full_snap_curr.captured_at,
                value_name="ProxyServer",
                old_value=prev_snap_guard.proxy_server,
                new_value=curr_snap_guard.proxy_server,
            ).to_jsonable(),
        ]
        evidence_rows.extend(
            x.to_jsonable()
            for x in build_connectivity_evidence(
                observed_at=full_snap_curr.captured_at,
                validation=validation,
            )
        )
        final_decision["evidence"] = evidence_rows

        emit_pipeline_audit_v1(
            repo_root,
            {
                "schema_version": "1",
                "event": "proxy_change_detected",
                "timestamp": full_snap_curr.captured_at,
                "before": proxy_state_audit_dict(prev_snap_guard),
                "after": proxy_state_audit_dict(curr_snap_guard),
                "attribute": heuristic_attribution_to_audit_dict(heuristic_pipeline),
                "policy": policy_payload_for_audit(
                    gd,
                    curr_snap=curr_snap_guard,
                    parsed_after=parsed_after,
                    final_decision=final_decision,
                ),
                "rollback": rollback_audit_payload,
                "connectivity_validation": validation.to_jsonable(),
                "evidence": evidence_rows,
            },
        )

        now_iso = full_snap_curr.captured_at
        policy_payload = gd.to_jsonable()
        policy_payload["proxy_path_operational"] = path_assessment.to_jsonable()

        audit_row = ProxyGuardAuditRecord(
            schema_version=2,
            timestamp=now_iso,
            event="proxy_guard_change",
            before_snapshot=prev_snap_guard.to_jsonable(),
            after_snapshot=curr_snap_guard.to_jsonable(),
            attribution=attrib.to_jsonable(),
            policy_decision=policy_payload,
            rollback_plan=rb_plan_obj.to_jsonable(),
            rollback_result=rb_res.to_jsonable(),
            safety_notes=(
                "no_firewall_changes",
                "no_adapter_mutations",
                "no_shell_command_injection_via_guard",
            ),
        )
        emit_proxy_guard_audit(audit_row, repo_root=repo_root)

        primary_name = attrib.process.name if attrib.process else None
        ctl = proxy_guard_control_event(
            event_type="registry_change",
            previous_registry_view=prev_view,
            current_registry_view=curr_view,
            attribution=attrib.to_jsonable(),
            policy_source=str(cfg.policy.source_path),
            decision=gd.decision if gd.decision != "observe" else "observe",
            decision_detail=f"{gd.reason}|attr_mode={attrib.mode}|confidence={attrib.confidence}",
            action=action,
            matched_rule=gd.matched_rule,
            primary_process_name=primary_name,
            rollback_detail=rollback_detail,
            post_rollback_registry_view=post_rb_view,
            probe_notes=attr_notes if attr_notes else None,
            rollback_suppressed_reason=suppressed_reason,
        )
        append_jsonl(cfg.jsonl_path, ctl)
        registry_change_events += 1
        stdout_blob = summarize_stdout_event(
            gd,
            rollback_subtree=rollback_audit_payload,
            curr_snap=curr_snap_guard,
            parsed_after=parsed_after,
            final_decision=final_decision,
        )
        stdout_blob["detail"] = gd.reason
        stdout_blob["legacy_decision_code"] = gd.decision
        stdout_blob["action"] = action
        stdout_blob["rollback_suppressed_reason"] = suppressed_reason
        if getattr(cfg, "stdout_json", False):
            print(json.dumps(stdout_blob, indent=2, ensure_ascii=False))
        else:
            print(format_proxy_guard_change(audit_row.to_jsonable()))
        prior_connectivity = post_connectivity

        if cfg.exit_after_registry_change_events is not None:
            if registry_change_events >= cfg.exit_after_registry_change_events:
                return
        if cfg.once:
            return
        time.sleep(cfg.interval_seconds)

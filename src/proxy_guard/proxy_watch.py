"""HKCU WinINET drift polling with process correlation and probabilistic attribution.

Module responsibility:
    Runs the ``python -m src proxy-watch`` polling loop: capture WinINET snapshots, classify
    transitions, collect process inventory, rank attribution candidates, append audit JSONL, and print
    human-readable alerts to stderr.

System placement:
    Called from :func:`~src.command_handlers.cmd_proxy_watch`. Depends on
    :mod:`~src.proxy_guard.state`, :mod:`~src.proxy_guard.wininet_change_diff`,
    :mod:`~src.proxy_guard.process_inventory`, :mod:`~src.proxy_guard.change_attribution`, and
    :func:`~src.proxy_guard.audit.emit_proxy_change_detected_audit`.

Key invariants:
    * This module never mutates the registry or network stack.
    * ``auto_rollback`` read from policy never performs a live rollback here—only emits an advisory
      stderr banner pointing operators to gated restore commands.
    * ``soak_minutes > 0`` bounds the loop and emits ``watch_soak_result`` (rewrite stickiness
      observation — not writer proof).

Input assumptions:
    * ``prior_state`` starts as ``None`` so the initial poll establishes baseline without logging drift.

Output guarantees:
    * Emits one JSON document to stdout on the first poll: ``{"event": "initial_poll", ...}`` with
      ``timestamp_utc`` from :func:`~src.core.time_utils.utc_now_iso`.
    * One JSONL audit row per detected drift cycle (schema in :mod:`~src.proxy_guard.audit`).

Side effects:
    * Indirect subprocess execution via injected ``run`` into snapshot/inventory callers (typically
      ``reg query``, PowerShell, and argv-only probing per those modules—not ``shell=True`` here).

Failure modes:
    * Unreadable policy JSON files are skipped; defaults apply (see ``load_watch_policy``).
    * Attribution confidence may be near zero when CIM snapshots or listener probes fail downstream.

Audit Notes:
    * Review ``logs/proxy_guard.jsonl`` beside stderr banners when investigating unexpected proxy
      flips—timestamps tie human output to persisted ``diff``/``attribution`` payloads without claiming
      registry-write proof (see attribution ``limitations`` in nested JSON).

Engineering Notes:
    * Keeps attribution and policy separate: risk tiering stays in ``diff_wininet_states`` outputs;
      ``evidence_boost`` adjusts scoring mass only inside ``attribute_proxy_change``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core.time_utils import utc_now_iso
from ..correlation.proxy_causation import analyze_proxy_causation
from ..network_state import event_log as reliability_v2
from .audit import emit_proxy_change_detected_audit
from .change_attribution import attribute_proxy_change
from .process_snapshot_enrichment import capture_enriched_process_snapshot
from .state import snapshot_wininet_state
from .wininet_change_diff import diff_wininet_states


@dataclass(frozen=True)
class WatchSoakResult:
    """Outcome of a bounded ``proxy-watch`` soak (read-only).

    Status values:
        * ``STABLE`` — no WinINET drift during the window.
        * ``CHANGED`` — one or more drifts observed; ProxyEnable did not flip 0→1
          (or baseline was already enabled).
        * ``REWRITE_DETECTED`` — ProxyEnable moved from disabled (0) to enabled (1).
        * ``SOAK_SKIPPED`` — soak_minutes <= 0 (caller used unbounded / ``--once`` path).
    """

    status: str
    soak_minutes: float
    poll_seconds: float
    samples: int
    changes_observed: int
    detail: str
    baseline_proxy_enable: int | None
    last_proxy_enable: int | None

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
            "status": self.status,
            "soak_minutes": self.soak_minutes,
            "poll_seconds": self.poll_seconds,
            "samples": self.samples,
            "changes_observed": self.changes_observed,
            "detail": self.detail,
            "baseline_proxy_enable": self.baseline_proxy_enable,
            "last_proxy_enable": self.last_proxy_enable,
        }


def load_watch_policy(repo_root: Path) -> dict[str, Any]:
    """Resolve operator policy for ``proxy-watch`` drift decisions and attribution nudges.

    Args:
        repo_root: Toolkit checkout root containing ``config/`` / ``shared/``.

    Returns:
        Dictionary with ``allowed_process_names``, ``allowed_exe_paths``, ``blocked_process_names``,
        ``allowed_proxy_ports``, ``deny_unknown_localhost_proxy``, ``auto_rollback``
        (and any extra keys callers forward—unknown keys are ignored by this module unless used
        downstream). Returns conservative defaults when no readable JSON exists.

    Side effects:
        Reads up to four candidate paths; opens each at most once. Never writes policy files.

    Failure modes:
        Missing files or ``JSONDecodeError`` skip that path; ``OSError`` on read skips that path.

    Raises:
        None intentionally—always returns a dict suitable for ``diff_wininet_states`` /
        ``attribute_proxy_change``.
    """

    candidates = [
        repo_root / "config" / "proxy_policy.json",
        repo_root / "config" / "proxy_policy.example.json",
        repo_root / "shared" / "proxy_policy.example.json",
    ]
    seen: Path | None = None
    for p in candidates:
        if not p.is_file():
            continue
        try:
            blob = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(blob, dict):
            seen = p
            return dict(blob)
    _ = seen
    return {
        "allowed_process_names": [],
        "allowed_exe_paths": [],
        "blocked_process_names": [],
        "allowed_proxy_ports": [],
        "deny_unknown_localhost_proxy": True,
        "auto_rollback": False,
    }


def _decide_action(policy: dict[str, Any], diff: dict[str, Any]) -> dict[str, str]:
    """Map classifier ``risk_level`` plus policy knobs into opaque ``decision`` JSON for audit logs.

    Args:
        policy: Loaded watch policy blob (typically includes ``auto_rollback`` bool).
        diff: Structured diff containing ``changed`` and ``risk_level``.

    Returns:
        Dict with string keys ``action`` ∈ ``observe`` | ``alert`` | ``rollback_recommended``
        (when ``auto_rollback`` is true alongside high risk, without executing rollback) and
        ``reason`` explaining the coarse operator hint.

    Side effects:
        None—pure branching on provided dict contents.

    Audit Notes:
        Values are persisted verbatim under JSONL ``decision``; they do **not** trigger automated
        repair paths in ``run_proxy_watch_loop``.
    """
    changed = bool(diff.get("changed"))
    risk = str(diff.get("risk_level") or "low")

    auto_rb = bool(policy.get("auto_rollback"))
    if not changed:
        return {"action": "observe", "reason": "no_proxy_core_change"}

    if auto_rb and risk == "high":
        return {
            "action": "rollback_recommended",
            "reason": "policy_auto_rollback_flag_set_but_execution_remains_confirmation_gated_elsewhere",
        }
    if risk == "high":
        return {"action": "alert", "reason": "high_risk_proxy_transition"}
    if risk == "medium":
        return {"action": "alert", "reason": diff.get("reason") or "medium_risk_proxy_transition"}
    return {"action": "observe", "reason": diff.get("reason") or "low_risk_transition"}


def _localhost_health_for_watch(
    *,
    now_state: dict[str, Any],
    port_int: int | None,
    attribution: dict[str, Any],
) -> dict[str, Any] | None:
    """Read-only localhost proxy health envelope for audit JSON (stdlib probes)."""
    parsed = now_state.get("parsed_proxy_server") or {}
    if not parsed.get("is_localhost_proxy") or port_int is None:
        return None
    from windows_network_toolkit.proxy_health import (
        build_proxy_health_audit_payload,
        check_localhost_proxy_health,
        classify_incident_from_health,
    )

    host = str(parsed.get("localhost_host") or "127.0.0.1")
    suspect = attribution.get("primary_suspect") if isinstance(attribution, dict) else None
    proc = None
    if isinstance(suspect, dict) and suspect.get("pid"):
        proc = {
            "pid": suspect.get("pid"),
            "name": suspect.get("name"),
            "exe_path": suspect.get("exe"),
            "cmdline": suspect.get("cmdline"),
        }
    owner = {"listener_found": proc is not None, "process": proc}
    wininet_state = {
        "wininet_proxy_enabled": bool(now_state.get("proxy_enable")),
        "wininet_proxy_server": now_state.get("proxy_server"),
        "winhttp_direct_access": now_state.get("winhttp_direct_access"),
    }
    health = check_localhost_proxy_health(host, port_int, listener_info=owner, timeout_seconds=5.0)
    classification = classify_incident_from_health(
        health,
        wininet_enabled=bool(now_state.get("proxy_enable")),
        winhttp_mismatch=bool(now_state.get("proxy_enable") and now_state.get("winhttp_direct_access")),
    )
    return build_proxy_health_audit_payload(
        wininet=wininet_state,
        health=health,
        classification=classification,
        extra_evidence=["Health check via proxy-watch localhost transition"],
    )


def _print_human_banner(
    *,
    diff: dict[str, Any],
    attribution: dict[str, Any],
    decision: dict[str, str],
    health_audit: dict[str, Any] | None = None,
) -> None:
    """Format drift, attribution envelope, and policy decision onto stderr for terminal operators.

    Args:
        diff: Structured diff including ``changed_fields``, ``risk_level``, ``before``/``after`` slices.
        attribution: Output of :func:`~src.proxy_guard.change_attribution.attribute_proxy_change`.
        decision: Output of :func:`_decide_action` (``action`` / ``reason``).

    Returns:
        None.

    Side effects:
        Prints multiple lines to ``sys.stderr`` only (stdout reserved for machine JSON elsewhere).
    """

    before = diff.get("before") or {}
    after = diff.get("after") or {}
    msg = ["", "[PROXY CHANGE DETECTED]"]
    if "ProxyServer" in (diff.get("changed_fields") or []):
        msg.append("ProxyServer changed:")
        msg.append(f"  before: {before.get('proxy_server')}")
        msg.append(f"  after: {after.get('proxy_server')}")
    if "ProxyEnable" in (diff.get("changed_fields") or []):
        msg.append(f"ProxyEnable: {before.get('proxy_enable')} -> {after.get('proxy_enable')}")
    msg.append("")
    msg.append(f"Risk: {str(diff.get('risk_level') or 'unknown').upper()}")

    health = (health_audit or {}).get("health") if health_audit else None
    if health:
        msg.append("")
        msg.append("Proxy health:")
        msg.append(f"  Status: {health.get('proxy_status', 'INSUFFICIENT_DATA')}")
        msg.append(f"  TCP listener: {'yes' if health.get('tcp_listening') else 'no'}")
        if health.get("listener_name"):
            msg.append(f"  Listener process: {health.get('listener_name')} PID {health.get('listener_pid')}")
        msg.append(
            f"  Proxy HTTPS CONNECT: {'ok' if health.get('proxy_https_connect_ok') else 'failed'}"
        )
        msg.append(f"  Direct HTTPS: {'ok' if health.get('direct_probe_ok') else 'failed'}")
        cls = (health_audit or {}).get("classification") or {}
        if cls.get("human_interpretation"):
            msg.append(f"  Interpretation: {cls.get('human_interpretation')}")

    suspect = attribution.get("primary_suspect") if isinstance(attribution, dict) else None
    msg.append("")
    msg.append("Likely process / correlation only:")
    if isinstance(suspect, dict):
        msg.append(f"  PID: {suspect.get('pid')}")
        msg.append(f"  Name: {suspect.get('name')}")
        msg.append(f"  Path: {suspect.get('exe')}")
        msg.append(f"  Parent: {suspect.get('parent_name')}")
        msg.append(f"  Confidence: {attribution.get('confidence')}")
    else:
        msg.append("  (no confident scorer match — see attribution JSON)")
    msg.append("")
    msg.append("Evidence:")
    for line in attribution.get("evidence") or []:
        msg.append(f"- {line}")
    msg.append("")
    msg.append(f"Recommended policy action: {decision.get('action')} — {decision.get('reason')}")
    print("\n".join(msg), file=sys.stderr)


def _run_causation_and_print(
    *,
    repo_root: Path,
    diff: dict[str, Any],
    attribution: dict[str, Any],
    port_int: int | None,
    run: Callable[..., Any],
) -> dict[str, Any] | None:
    """Sysmon registry-write attribution for high-risk transitions (read-only)."""
    risk = str(diff.get("risk_level") or "low").lower()
    if risk != "high":
        return None
    before = diff.get("before") or {}
    after = diff.get("after") or {}
    suspect = attribution.get("primary_suspect") if isinstance(attribution, dict) else None
    listener = suspect if isinstance(suspect, dict) else None
    result = analyze_proxy_causation(
        timestamp_utc=utc_now_iso(),
        before_state=before,
        after_state=after,
        changed_fields=list(diff.get("changed_fields") or []),
        observed_localhost_port=port_int,
        listener_process=listener,
        run=run,
        repo_root=repo_root,
    )
    if result.causation_level == "FINAL_CAUSATION":
        print(
            f"FINAL CAUSATION: {result.writer_process} wrote "
            f"{result.matched_registry_target} = {result.matched_registry_details}",
            file=sys.stderr,
        )
    elif result.causation_level in ("CORRELATION_ONLY", "UNKNOWN"):
        print(
            "Likely process / correlation only; registry writer proof unavailable",
            file=sys.stderr,
        )
    return result.to_dict()


def _emit_v2_watch_events(
    repo_root: Path,
    *,
    diff: dict[str, Any],
    attribution: dict[str, Any],
) -> None:
    """Append reliability v2 drift/attribution rows (best-effort; never raises to callers).

    Implements policy: listener evidence correlates processes to ports—it does **not**
    prove registry-authorship absent separate registry-write forensic evidence.
    """

    try:
        before_f = diff.get("before") or {}
        after_f = diff.get("after") or {}
        pe_before = before_f.get("proxy_enable")
        pe_after = after_f.get("proxy_enable")

        srv_raw = after_f.get("proxy_server")
        srv = srv_raw.strip() if isinstance(srv_raw, str) else (str(srv_raw) if srv_raw is not None else "")
        normalized_after = {
            "ProxyEnable": pe_after,
            "ProxyServer": after_f.get("proxy_server"),
            "AutoConfigURL": after_f.get("auto_config_url"),
            "AutoDetect": after_f.get("auto_detect"),
            "ProxyOverride": after_f.get("proxy_override"),
        }
        parsed_after = reliability_v2.parse_proxy(normalized_after)

        hypothesis_s = str(parsed_after.get("proxy_mode") or "manual_localhost")

        host = str(parsed_after.get("localhost_host") or "127.0.0.1")
        port_hint = parsed_after.get("localhost_port")
        corr = reliability_v2.correlation_key(srv if srv else None)
        incident = reliability_v2.incident_id_from_proxy(srv if srv else None)

        suspect = attribution.get("primary_suspect") if isinstance(attribution, dict) else None
        pid_i: int | None = None
        proc_name_s: str | None = None
        proc_path: str | None = None
        cmdline: str | None = None
        if isinstance(suspect, dict):
            pid_any = suspect.get("pid")
            try:
                pid_i = int(pid_any) if pid_any is not None else None
            except (TypeError, ValueError):
                pid_i = None
            proc_name_s = str(suspect.get("name") or suspect.get("process_name") or "") or None
            if suspect.get("exe"):
                proc_path = str(suspect.get("exe"))
            cli = suspect.get("command_line")
            if isinstance(cli, str):
                cmdline = cli

        if isinstance(port_hint, int):
            evt_conf = attribution.get("confidence") if isinstance(attribution, dict) else None
            conf_f = 0.55
            if isinstance(evt_conf, (float, int)):
                conf_f = float(evt_conf)
            elif evt_conf is not None:
                try:
                    conf_f = float(str(evt_conf))
                except ValueError:
                    conf_f = 0.55
            limits = [
                "Listener attribution shows which process held the inferred proxy port.",
                "It does not prove that process authored the HKCU ProxyEnable change without registry-write forensic evidence.",
            ]
            evid = {
                "listener_found": pid_i is not None,
                "pid": pid_i,
                "process_name": proc_name_s,
                "process_path": proc_path,
                "command_line": cmdline,
                "startup_match": None,
                "scheduled_task_match": None,
            }
            reliability_v2.log_attribution(
                repo_root,
                incident_id=incident,
                correlation_key_val=corr,
                target={"host": host, "port": port_hint},
                evidence=evid,
                hypothesis=hypothesis_s,
                confidence=conf_f,
                limits=limits,
            )

        if pe_before == 0 and pe_after == 1:
            rc = reliability_v2.count_drift_events(repo_root, corr, "proxy_reenabled") + 1
            reliability_v2.log_drift(
                repo_root,
                drift_type="proxy_reenabled",
                incident_id=incident,
                correlation_key_val=corr,
                previous_known_good={"ProxyEnable": 0},
                current={
                    "ProxyEnable": pe_after,
                    "ProxyServer": after_f.get("proxy_server"),
                },
                repeat_count=rc,
                confidence=0.95,
                interpretation=(
                    "WinINET proxy was re-enabled after ProxyEnable indicated disabled. "
                    "Repair appears temporary—look for startup items, VPN/corporate policy, browser extensions, "
                    "or tooling that rewrites HKCU proxy keys."
                ),
            )
            reliability_v2.update_or_write_incident_summary(
                repo_root,
                incident_id=incident,
                correlation_key_val=corr,
                symptom={
                    "proxy_server": srv or after_f.get("proxy_server"),
                    "proxy_mode": parsed_after.get("proxy_mode"),
                    "proxy_reenabled_repeatedly": True,
                },
                counters_patch={"drift_events": 1, "unique_ports": [parsed_after["localhost_port"]]}
                if isinstance(parsed_after.get("localhost_port"), int)
                else {"drift_events": 1},
                assessment={
                    "repair_effectiveness": "temporary_success",
                    "root_cause_status": "unknown",
                    "likely_category": "external_reapply_mechanism",
                    "confidence": 0.9,
                },
                recommended_next_actions=[
                    "Identify process listening on the loopback proxy port",
                    "Check startup entries",
                    "Check scheduled tasks",
                    "Check browser/VPN/proxy tools",
                    "Monitor registry value changes over time",
                ],
            )
    except Exception:
        return


def _run_final_causation_if_enabled(
    *,
    repo_root: Path,
    diff: dict[str, Any],
    run: Callable[..., Any],
    enabled: bool,
) -> dict[str, Any] | None:
    """Collect final causation report on drift (best-effort; never blocks watch loop)."""
    if not enabled:
        return None
    try:
        from .final_causation import collect_final_causation

        report = collect_final_causation(
            repo_root=repo_root,
            proxy_change={"diff": diff},
            run=run,
        )
        print(
            f"[final-causation] {report.verdict} ({report.proof_level}): {report.root_cause_sentence}",
            file=sys.stderr,
        )
        return report.to_dict()
    except Exception as exc:
        print(f"[final-causation] skipped: {exc}", file=sys.stderr)
        return None


def _proxy_enable_int(state: dict[str, Any] | None) -> int | None:
    if not state:
        return None
    raw = state.get("proxy_enable")
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def run_proxy_watch_loop(
    *,
    repo_root: Path,
    interval_seconds: float,
    once: bool,
    run: Callable[..., Any] = subprocess.run,
    evidence_boost: float = 0.0,
    final_causation: bool = False,
    soak_minutes: float = 0.0,
    exit_on_rewrite: bool = True,
    sleep_fn: Callable[[float], None] = time.sleep,
    monotonic_fn: Callable[[], float] = time.monotonic,
) -> WatchSoakResult | None:
    """Poll WinINET snapshots until interrupted, ``--once``, or a soak deadline.

    Args:
        repo_root: Toolkit root hosting ``logs/`` for JSONL sinks and ``config/`` for optional policy.
        interval_seconds: Sleep between polls; clamped downstream to ``>= 1.0`` seconds.
        once: When True, terminates after baseline plus one drift-check cycle (still prints
            ``initial_poll`` once). Ignored when ``soak_minutes > 0``.
        run: Injectable ``subprocess.run`` surrogate for tests (passed through to snapshot/inventory).
        evidence_boost: Additive score mass forwarded to ``attribute_proxy_change``
            (typically from optional Procmon CSV path parsed by CLI before calling this routine).
        final_causation: When True, run final causation collector on each drift.
        soak_minutes: When ``> 0``, poll for that many minutes then exit with a
            :class:`WatchSoakResult` (short soak for rewrite detection).
        exit_on_rewrite: When soaking, stop early if ``ProxyEnable`` flips ``0 → 1``.
        sleep_fn: Injectable sleep for tests.
        monotonic_fn: Injectable monotonic clock for tests.

    Returns:
        :class:`WatchSoakResult` when ``soak_minutes > 0``; otherwise ``None`` (unbounded /
        ``--once`` interactive paths).

    Side effects:
        Writes append-only NDJSON lines to ``logs/proxy_guard.jsonl`` via
        ``emit_proxy_change_detected_audit`` whenever ``diff.changed`` is true (after baseline).
        Writes human summaries to stderr. First iteration emits JSON to stdout once.
        Soak completion also emits a ``watch_soak_result`` JSON object to stdout.

    Raises:
        None by design—subprocess faults are swallowed within snapshot/inventory layers.

    Audit Notes:
        Correlate stdout ``initial_poll`` ``state`` with subsequent JSONL timestamps when narrowing
        which configuration transition caused user-visible breakage. Soak status is observation of
        registry stickiness, not writer proof — pair with Procmon/Sysmon for attribution.
    """

    policy = load_watch_policy(repo_root)
    prior_state: dict[str, Any] | None = None
    printed_poll = False
    soaking = soak_minutes > 0
    deadline = (monotonic_fn() + soak_minutes * 60.0) if soaking else None
    samples = 0
    changes_observed = 0
    baseline_enable: int | None = None
    last_enable: int | None = None
    rewrite_detected = False
    poll_seconds = max(1.0, float(interval_seconds))

    while True:
        now_state = snapshot_wininet_state(run=run)
        samples += 1
        last_enable = _proxy_enable_int(now_state)
        if baseline_enable is None:
            baseline_enable = last_enable

        if prior_state is not None:
            diff = diff_wininet_states(prior_state, now_state, policy=policy)
            if diff.get("changed"):
                changes_observed += 1
                prior_en = _proxy_enable_int(prior_state)
                if prior_en == 0 and last_enable == 1:
                    rewrite_detected = True

                parsed = now_state.get("parsed_proxy_server") or {}
                port_hint = parsed.get("localhost_port")
                port_int = None
                if isinstance(port_hint, int):
                    port_int = port_hint
                elif isinstance(port_hint, str) and port_hint.strip().isdigit():
                    port_int = int(port_hint.strip())

                inventory = capture_enriched_process_snapshot(proxy_localhost_port=port_int, run=run)
                attribution = attribute_proxy_change(
                    proxy_diff=diff,
                    current_state=now_state,
                    inventory=inventory,
                    policy=policy,
                    evidence_confidence_boost=evidence_boost,
                )
                health_audit = _localhost_health_for_watch(
                    now_state=now_state,
                    port_int=port_int,
                    attribution=attribution,
                )
                if health_audit:
                    attribution = {**attribution, "health_audit": health_audit}

                decision = _decide_action(policy, diff)
                causation_blob = _run_causation_and_print(
                    repo_root=repo_root,
                    diff=diff,
                    attribution=attribution,
                    port_int=port_int,
                    run=run,
                )
                final_blob = _run_final_causation_if_enabled(
                    repo_root=repo_root,
                    diff=diff,
                    run=run,
                    enabled=final_causation,
                )
                emit_proxy_change_detected_audit(
                    repo_root,
                    diff=diff,
                    attribution=attribution,
                    decision=decision,
                    causation=causation_blob,
                    final_causation=final_blob,
                )
                _emit_v2_watch_events(repo_root, diff=diff, attribution=attribution)
                _print_human_banner(diff=diff, attribution=attribution, decision=decision, health_audit=health_audit)

                if bool(policy.get("auto_rollback")):
                    banner = (
                        "[policy] auto_rollback=true but proxy-watch never executes live "
                        "rollback here — use proxy-guard or typed restores."
                    )
                    print(banner, file=sys.stderr)

                if soaking and exit_on_rewrite and rewrite_detected:
                    prior_state = now_state
                    break

        prior_state = now_state

        if not printed_poll:
            print(
                json.dumps(
                    {"event": "initial_poll", "timestamp_utc": utc_now_iso(), "state": prior_state},
                    indent=2,
                ),
                flush=True,
            )
            printed_poll = True

        if soaking:
            assert deadline is not None
            if rewrite_detected and exit_on_rewrite:
                break
            if monotonic_fn() >= deadline:
                break
            remaining = deadline - monotonic_fn()
            if remaining <= 0:
                break
            sleep_fn(min(poll_seconds, remaining))
            continue

        if once:
            break
        sleep_fn(poll_seconds)

    if not soaking:
        return None

    if rewrite_detected:
        status = "REWRITE_DETECTED"
        detail = (
            "ProxyEnable flipped from 0 to 1 during soak. Suspected active reverter. "
            "Capture Procmon/Sysmon for writer proof; do not loop proxy-disable."
        )
    elif changes_observed > 0:
        status = "CHANGED"
        detail = f"Observed {changes_observed} WinINET drift event(s); ProxyEnable did not flip 0→1."
    else:
        status = "STABLE"
        detail = "no_wininet_drift_during_soak"

    result = WatchSoakResult(
        status=status,
        soak_minutes=float(soak_minutes),
        poll_seconds=poll_seconds,
        samples=samples,
        changes_observed=changes_observed,
        detail=detail,
        baseline_proxy_enable=baseline_enable,
        last_proxy_enable=last_enable,
    )
    print(
        json.dumps({"event": "watch_soak_result", **result.to_dict()}, indent=2),
        flush=True,
    )
    return result

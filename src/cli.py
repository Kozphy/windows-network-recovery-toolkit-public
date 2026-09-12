"""Argparse routers for ``python -m src``; delegates execution to ``src.command_handlers``.

Module responsibility:
    Register subcommands (legacy diagnostics, Proxy Guard, live hypothesis exports, repair previews/replay wrappers,
    proof probes) and map ``Namespace`` objects to handler callables defined outside this module for testability.

System placement:
    Sits atop ``src.diagnostics`` collectors, ``src.hypothesis`` scoring, optional ``src.proof`` checks, persistence
    helpers under ``src.logging``, and toolkit-specific remediation preview logic routed through handlers. FastAPI
    demo APIs live separately under ``backend/``—not imported here unless tests patch.

Pipeline position:
    Legacy path: collectors → ``hypothesis.v1_scoring`` (via ``decision_engine.scoring`` shim) →
    ``src.recommendations.build_recommendations`` → artefacts. Live path: handlers orchestrate snapshots, scoring,
    policy, proof, and audits (see ``cmd_diagnose_live`` docstring).

Side effects:
    This module performs no filesystem writes directly; delegated handlers mutate ``reports/`` and ``logs/`` per command.

Key invariants:
    Audit fingerprints truncate SHA-256 digests rather than emitting raw hostname strings where documented.

    ``repair-safe --apply`` elevates LOW-risk scripts only after ``RUN``; firewall resets remain outside this shortcut.

Failure modes:
    Missing ``reports/last_diagnosis.json`` surfaces ``FileNotFoundError`` for explain/recommend/export until
    ``diagnose`` populates artefacts.

Audit Notes:
    Legacy ``diagnose`` appends ``logs/decision_audit.jsonl`` rows and replaces ``reports/last_diagnosis.json``.

    ``proxy-watch`` tails HKCU churn into ``logs/proxy_guard.jsonl`` (`schema_version=1`) for attribution replays.

    Live commands refresh ``reports/snapshots/*.json``, ``reports/last_diagnosis_live.json``,
    ``logs/decision_runs.jsonl`` (replayable audits), companion JSONL tails, ``logs/network_snapshots.jsonl``,
    ``logs/repair_audit.jsonl`` for guarded registry flows, optionally ``logs/proxy_guard_*`` artefacts.

See Also:
    ``docs/cli_reference.md``, ``docs/decision_engine_v2.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from edge_device.cli_handlers import cmd_edge_diagnose, cmd_edge_replay

from .command_handlers import (
    cmd_diagnose_live,
    cmd_procmon_filter_set,
    cmd_proxy_attribution,
    cmd_proxy_causation,
    cmd_proxy_classify,
    cmd_proxy_diagnose,
    cmd_proxy_disable,
    cmd_proxy_forensics,
    cmd_proxy_guard,
    cmd_proxy_investigate,
    cmd_proxy_monitor,
    cmd_proxy_owner,
    cmd_proxy_path_status,
    cmd_proxy_policy,
    cmd_proxy_report,
    cmd_proxy_rollback,
    cmd_proxy_snapshot_diff,
    cmd_proxy_snapshot_list,
    cmd_proxy_snapshot_restore,
    cmd_proxy_snapshot_save,
    cmd_proxy_snapshot_show,
    cmd_proxy_status,
    cmd_proxy_stop_listener,
    cmd_proxy_stop_reverter,
    cmd_proxy_timeline,
    cmd_proxy_watch,
    cmd_proxy_watch_report,
    cmd_repair_apply,
    cmd_repair_preview,
    cmd_replay_live_run,
    cmd_snapshot,
)
from .command_handlers_safety import (
    cmd_agent_next_step,
    cmd_proxy_config_check,
    cmd_proxy_registry_writer_proof,
    cmd_proxy_restore_lkg,
)
from .demo_handlers import SCENARIOS, cmd_demo_scenario
from .diagnostics.collector import collect_features, load_features_json
from .diagnostics.features import FeatureVector
from .hypothesis.v1_scoring import CauseScore, DecisionResult, explain_primary, score_root_causes
from .logging.audit import append_jsonl
from .logging.feedback import FeedbackRecord, FeedbackState, append_feedback
from .network_recovery.cli_handlers import (
    cmd_diagnose_app,
    cmd_preview_scenario,
    cmd_remediate_scenario,
)
from .network_state.cli_handlers import (
    cmd_network_state_diff,
    cmd_network_state_evidence_import,
    cmd_network_state_report,
    cmd_network_state_restore,
    cmd_network_state_snapshot_list,
    cmd_network_state_snapshot_save,
    cmd_network_state_snapshot_set_default,
    cmd_network_state_snapshot_show,
)
from .platform_handlers import (
    cmd_platform_decide,
    cmd_platform_events,
    cmd_platform_evidence,
    cmd_platform_metrics,
    cmd_platform_outcome,
    cmd_platform_replay,
)
from .production_handlers import (
    cmd_fleet_report,
    cmd_fleet_simulate,
    cmd_incident_review,
    cmd_policy_validate,
)
from .proof.proxy_https import run_localhost_proxy_https_proof
from .proxy_drift.handlers import (
    cmd_auto_fix_proxy,
    cmd_collect_evidence_bundle,
    cmd_dns_health,
    cmd_ensure_proxy_health,
    cmd_install_boot_trace_task,
    cmd_install_guardian_task,
    cmd_install_startup_observability,
    cmd_proxy_boot_trace,
    cmd_proxy_fix,
    cmd_proxy_guardian_drift,
    cmd_safe_search,
    cmd_startup_inventory,
    cmd_startup_observability_report,
    cmd_uninstall_boot_trace_task,
    cmd_uninstall_guardian_task,
    cmd_uninstall_startup_observability,
)
from .proxy_guard.linux_proxy_commands import cmd_proxy_linux_snapshot
from .recommendations.engine import RecommendationBundle, build_recommendations
from .version import SCRIPT_VERSION


def _repo_root(explicit: Path | None) -> Path:
    """Resolve toolkit repository root for report and log paths.

    Args:
        explicit: Optional path from ``--repo-root``; must point at the checkout.

    Returns:
        Absolute resolved ``Path`` to the repo root (parent of ``src/``).

    Raises:
        None.
    """
    if explicit:
        return explicit.resolve()
    return Path(__file__).resolve().parent.parent


def _parse_bool_arg(value: str | bool | None) -> bool:
    """Parse CLI boolean flags that accept explicit true/false strings."""

    if isinstance(value, bool):
        return value
    if value is None:
        return True
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def _add_proxy_stop_listener_arguments(parser: argparse.ArgumentParser, *, include_chained: bool = False) -> None:
    """Register shared flags for ``proxy-stop-listener`` and chained ``proxy-disable`` flows."""

    parser.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        help="Preview only by default. Use --dry-run false with --confirm STOP_PROXY_LISTENER to apply.",
    )
    parser.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="stop_listener_confirm_phrase",
        metavar="PHRASE",
        help="Live apply requires exact phrase STOP_PROXY_LISTENER.",
    )
    parser.add_argument("--port", type=int, default=None, help="Override port (defaults to parsed ProxyServer).")
    parser.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    parser.add_argument(
        "--stop-parent",
        action="store_true",
        dest="stop_parent_tree",
        help=(
            "Also terminate attributed parent powershell tree first (live apply requires "
            "--reverter-confirm STOP_PROXY_REVERTER in addition to STOP_PROXY_LISTENER)."
        ),
    )
    parser.add_argument(
        "--reverter-confirm",
        type=str,
        default="",
        dest="stop_reverter_confirm_phrase",
        metavar="PHRASE",
        help="Typed phrase STOP_PROXY_REVERTER when using --stop-parent on live apply.",
    )
    if include_chained:
        parser.add_argument(
            "--stop-listener-first",
            action="store_true",
            help="Before disable apply, run stop-listener (requires --stop-listener-confirm STOP_PROXY_LISTENER).",
        )
        parser.add_argument(
            "--stop-listener-confirm",
            type=str,
            default="",
            dest="stop_listener_confirm_phrase",
            metavar="PHRASE",
            help="Typed phrase STOP_PROXY_LISTENER when using --stop-listener-first on live apply.",
        )


def _add_proxy_stop_reverter_arguments(parser: argparse.ArgumentParser, *, include_chained: bool = False) -> None:
    """Register shared flags for ``proxy-stop-reverter`` and chained ``proxy-disable`` flows."""

    if include_chained:
        parser.add_argument(
            "--stop-reverter-first",
            action="store_true",
            help="Before disable apply, run stop-reverter (requires --stop-reverter-confirm STOP_PROXY_REVERTER).",
        )
        parser.add_argument(
            "--stop-reverter-confirm",
            type=str,
            default="",
            dest="stop_reverter_confirm_phrase",
            metavar="PHRASE",
            help="Typed phrase STOP_PROXY_REVERTER when using --stop-reverter-first on live apply.",
        )
        return

    parser.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        help="Preview only by default. Use --dry-run false with --confirm STOP_PROXY_REVERTER to apply.",
    )
    parser.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="stop_reverter_confirm_phrase",
        metavar="PHRASE",
        help="Live apply requires exact phrase STOP_PROXY_REVERTER.",
    )
    parser.add_argument("--port", type=int, default=None, help="Override port (defaults to parsed ProxyServer).")
    parser.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")


def _fingerprint() -> dict[str, str]:
    """Build a non-reversible machine key for audit correlation.

    Returns:
        Mapping with ``host_key_hash16``: first 16 hex chars of SHA-256 over
        ``node|release|machine``. Not a stable hardware ID across reinstalls.

    Raises:
        None.
    """
    raw = f"{platform.node()}|{platform.release()}|{platform.machine()}".encode()
    digest = hashlib.sha256(raw).hexdigest()[:16]
    return {"host_key_hash16": digest}


def _scores_dict(result: DecisionResult) -> dict[str, float]:
    """Project each cause to its scalar confidence for JSON snapshots.

    Args:
        result: Full scoring outcome from `score_root_causes`.

    Returns:
        Mapping of root-cause key to confidence in ``[0.0, 1.0]``.

    Raises:
        None.
    """
    return {k: v.confidence for k, v in result.scores_by_cause.items()}


def _serialize_cause(score: CauseScore) -> dict[str, Any]:
    """Flatten a scored cause into an audit/export-friendly dictionary.

    Args:
        score: One ``CauseScore`` entry.

    Returns:
        Dict with ``cause``, ``confidence``, ``evidence`` list.

    Raises:
        None.
    """
    return {
        "cause": score.cause,
        "confidence": score.confidence,
        "evidence": list(score.evidence),
    }


def _serialize_bundle(bundle: RecommendationBundle) -> dict[str, Any]:
    """Normalize all recommendation tiers for JSON payloads.

    Args:
        bundle: Tiered suggestion groups from `build_recommendations`.

    Returns:
        Dict with diagnose/repair-safe/guided/advanced arrays matching README naming.

    Raises:
        None.
    """

    def pack(items: tuple[Any, ...]) -> list[dict[str, Any]]:
        return [
            {
                "title": r.title,
                "detail": r.detail,
                "script": r.script_relative,
                "tier": r.tier,
                "risk": r.risk,
                "reversible_notes": r.reversible_notes,
            }
            for r in items
        ]

    return {
        "diagnose": pack(bundle.diagnose),
        "repair_safe": pack(bundle.safe),
        "guided_repair": pack(bundle.guided),
        "advanced_repair": pack(bundle.advanced),
    }


def _build_payload(
    *,
    diagnosis_id: str,
    features: FeatureVector,
    decision: DecisionResult,
    bundle: RecommendationBundle,
    commands_executed: list[dict[str, str]],
) -> dict[str, Any]:
    """Assemble the JSON-serializable snapshot written to reports and audit logs.

    Args:
        diagnosis_id: New UUID string for this run.
        features: Normalized ``FeatureVector`` from probes or fixture.
        decision: Full per-cause scoring outcome.
        bundle: Tiered recommendations for this primary cause.
        commands_executed: Probe command labels from live collection or fixture.

    Returns:
        Dict suitable for ``reports/last_diagnosis.json`` and audit subset.

    Raises:
        None.
    """
    primary = decision.primary()
    return {
        "diagnosis_id": diagnosis_id,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "script_version": SCRIPT_VERSION,
        "machine": _fingerprint(),
        "features": features.to_dict(),
        "confidence_by_cause": _scores_dict(decision),
        "ranked_root_causes": [_serialize_cause(s) for s in decision.ranked()],
        "selected_root_cause": primary.cause,
        "selected_confidence": primary.confidence,
        "selected_evidence": list(primary.evidence),
        "explain_sentence": explain_primary(primary, features),
        "recommendations": _serialize_bundle(bundle),
        "commands_executed": commands_executed,
    }


def _write_last_diagnosis(repo: Path, payload: dict[str, Any]) -> Path:
    """Persist the latest diagnosis snapshot (overwrites prior file).

    Side effects:
        Creates ``reports/`` if missing; overwrites ``last_diagnosis.json``.

    Args:
        repo: Repository root containing ``reports/``.
        payload: Full snapshot from `_build_payload`.

    Returns:
        Path to ``reports/last_diagnosis.json``.

    Raises:
        OSError: If the directory cannot be created or file cannot be written.
        TypeError: If payload is not JSON-serializable.
    """
    reports = repo / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    path = reports / "last_diagnosis.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _read_last_diagnosis(repo: Path) -> dict[str, Any]:
    """Load the persisted snapshot produced by the last ``diagnose`` command.

    Args:
        repo: Repository root containing ``reports/last_diagnosis.json``.

    Returns:
        Parsed diagnosis payload dictionary.

    Raises:
        FileNotFoundError: If no snapshot exists yet.
        json.JSONDecodeError: If file content is invalid JSON.
    """
    path = repo / "reports" / "last_diagnosis.json"
    if not path.is_file():
        raise FileNotFoundError(
            "No reports/last_diagnosis.json - run `python -m src diagnose` first, "
            "or use `diagnose-live` plus `--live` on explain, recommend, repair-safe, and export-report."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _audit(repo: Path, payload: dict[str, Any]) -> None:
    """Append a single diagnosis audit record (append-only JSONL).

    Side effects:
        Creates ``logs/`` if needed; appends one line to
        ``logs/decision_audit.jsonl``.

    Args:
        repo: Repository root.
        payload: Same structure as `_write_last_diagnosis` payload.

    Raises:
        TypeError / OSError: Propagated from `append_jsonl`.
    """
    audit_path = repo / "logs" / "decision_audit.jsonl"
    record = {
        "type": "diagnosis",
        "timestamp": datetime.now(UTC).isoformat(),
        "diagnosis_id": payload["diagnosis_id"],
        "script_version": SCRIPT_VERSION,
        "machine": payload["machine"],
        "features": payload["features"],
        "scores": payload["confidence_by_cause"],
        "selected_root_cause": payload["selected_root_cause"],
        "confidence": payload["selected_confidence"],
        "evidence": payload["selected_evidence"],
        "recommended_actions": payload["recommendations"],
        "commands_executed": payload["commands_executed"],
    }
    append_jsonl(audit_path, record)


def cmd_diagnose(args: argparse.Namespace) -> int:
    """Run scoring, persist ``last_diagnosis.json``, append audit JSONL, print summary.

    Input assumptions:
        ``--fixture`` points at JSON with ``FeatureVector`` fields (see
        `load_features_json`); live mode assumes Windows tooling used by the
        collector (``ping``, ``nslookup``, ``curl``, PowerShell).
        Use ``--live`` or ``--proof`` for the v2 live engine (same as ``diagnose-live``);
        ``--proof`` enables the Proof Engine (HTTPS localhost-proxy contrast).

    Raises:
        Propagates exceptions from collection, scoring, or I/O helpers.

    Returns:
        ``0`` on success.

    Audit Notes:
        Review ``logs/decision_audit.jsonl`` for the authoritative append-only
        trail; ``reports/last_diagnosis.json`` is overwritten each run.
    """
    app_target = (getattr(args, "app", None) or "").strip().lower()
    if app_target:
        if getattr(args, "live_engine", False) or getattr(args, "proof_engine", False) or getattr(args, "fixture", None):
            print("diagnose --app is incompatible with --live, --proof, and --fixture.", file=sys.stderr)
            return 2
        return cmd_diagnose_app(args)

    use_live = bool(getattr(args, "live_engine", False) or getattr(args, "proof_engine", False))
    if use_live:
        if getattr(args, "fixture", None):
            print(
                "diagnose: --fixture is only for legacy v1 mode; omit it when using --live or --proof, "
                "or run `python -m src diagnose-live` directly.",
                file=sys.stderr,
            )
            return 2
        if getattr(args, "json", False) and getattr(args, "both_formats", False):
            print("diagnose: use only one of --json or --both with --live/--proof.", file=sys.stderr)
            return 2
        live_ns = argparse.Namespace(
            repo_root=args.repo_root,
            emit_json=bool(getattr(args, "json", False)),
            emit_both=bool(getattr(args, "both_formats", False)),
            live_proofs=bool(getattr(args, "proof_engine", False)),
            replay_run_id=None,
        )
        return cmd_diagnose_live(live_ns)

    if getattr(args, "both_formats", False):
        print(
            "diagnose: --both is for live v2 output; add --live or --proof, or use `diagnose-live --both`.",
            file=sys.stderr,
        )
        return 2

    repo = _repo_root(args.repo_root)
    if not args.fixture and platform.system() != "Windows":
        print(
            "diagnose without --fixture requires Windows (live probes use reg, netsh, PowerShell, etc.). "
            "Use --fixture <features.json> on other platforms.",
            file=sys.stderr,
        )
        return 2
    if args.fixture:
        features = load_features_json(Path(args.fixture))
        commands_executed = [
            {"label": "fixture", "cmd": str(Path(args.fixture).resolve())},
        ]
    else:
        features, meta = collect_features(repo_root=repo)
        commands_executed = list(meta.get("commands_executed") or [])

    decision = score_root_causes(features)
    primary = decision.primary()
    bundle = build_recommendations(primary, features, repo)
    diagnosis_id = str(uuid.uuid4())
    payload = _build_payload(
        diagnosis_id=diagnosis_id,
        features=features,
        decision=decision,
        bundle=bundle,
        commands_executed=commands_executed,
    )
    _audit(repo, payload)
    last_path = _write_last_diagnosis(repo, payload)

    human = [
        "=== Windows Network Recovery Toolkit — diagnose (legacy v1) ===",
        "",
        "What this does",
        "--------------",
        "Collects connectivity/proxy/feature signals (or loads --fixture JSON), scores fixed v1 root-cause",
        "buckets (DNS, proxy, Winsock, …), persists reports/last_diagnosis.json, and appends logs/decision_audit.jsonl.",
        "Scores are heuristic confidences — not calibrated probabilities.",
        "",
        "For richer loopback-proxy / listener context and policy gates, prefer:",
        "  python -m src diagnose --live",
        "  python -m src diagnose --proof",
        "",
        f"Diagnosis ID: {diagnosis_id}",
        "",
        payload["explain_sentence"],
        "",
        "Root cause ranking (confidence):",
    ]
    for item in payload["ranked_root_causes"][:7]:
        human.append(f"  - {item['cause']}: {item['confidence']:.2f}")
    human.extend(
        [
            "",
            "Tiered recommendations:",
            "  - Diagnose:",
        ]
    )
    for rec in bundle.diagnose:
        human.append(f"    - [{rec.risk}] {rec.title}")
    human.append("  - Repair-safe:")
    for rec in bundle.safe:
        human.append(f"    - [{rec.risk}] {rec.title}")
    human.extend(["  - Guided repair:"])
    for rec in bundle.guided:
        human.append(f"    - [{rec.risk}] {rec.title}")
    human.extend(["  - Advanced repair (manual confirmation outside this CLI):"])
    for rec in bundle.advanced:
        human.append(f"    - [{rec.risk}] {rec.title}")
    human.extend(
        [
            "",
            f"Structured snapshot: {last_path}",
            "Audit log appended: logs\\decision_audit.jsonl",
        ]
    )

    print("\n".join(human))
    if getattr(args, "json", False):
        print("\nJSON_PAYLOAD_START")
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        print("JSON_PAYLOAD_END")
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Offline replay CLI entry (wraps ``cmd_replay_live_run``)."""
    pid = getattr(args, "replay_positional_id", None)
    rid = (str(pid).strip() if pid is not None else "") or ""
    alt = getattr(args, "replay_flag_id", None)
    if isinstance(alt, str) and alt.strip():
        rid = rid or alt.strip()
    ej = bool(getattr(args, "emit_json", False))
    eb = bool(getattr(args, "emit_both", False))
    if ej and eb:
        print("replay: use only one of --json or --both.", file=sys.stderr)
        return 2
    if not rid:
        print(
            "replay: missing RUN_ID — try: python -m src replay <uuid>   or   python -m src replay --run-id <uuid>",
            file=sys.stderr,
        )
        return 2
    ns = argparse.Namespace(
        repo_root=args.repo_root,
        replay_run_id=rid,
        emit_json=ej,
        emit_both=eb,
    )
    return cmd_replay_live_run(ns)


def cmd_remediate(args: argparse.Namespace) -> int:
    """App-path scenario remediation preview (dry-run default)."""
    return cmd_remediate_scenario(args)


def cmd_preview(args: argparse.Namespace) -> int:
    """Repair tier preview CLI entry (`preview` ≡ `repair-preview`)."""
    if getattr(args, "scenario", None):
        ns = argparse.Namespace(
            repo_root=args.repo_root,
            scenario=args.scenario,
            emit_json=bool(getattr(args, "emit_json_preview", False)),
            recovery_feedback=getattr(args, "recovery_feedback", None),
        )
        return cmd_preview_scenario(ns)

    ej = bool(getattr(args, "emit_json_preview", False))
    eb = bool(getattr(args, "emit_both_preview", False))
    if ej and eb:
        print("preview: use only one of --json or --both.", file=sys.stderr)
        return 2
    ns = argparse.Namespace(
        repo_root=args.repo_root,
        emit_json_preview=ej,
        emit_both_preview=eb,
    )
    return cmd_repair_preview(ns)


def cmd_explain(args: argparse.Namespace) -> int:
    """Print the rationale sentence plus primary evidence bullets from the last diagnose.

    Raises:
        FileNotFoundError: When ``reports/last_diagnosis.json`` is absent.
        json.JSONDecodeError: When snapshot content is malformed.

    Returns:
        Shell exit ``0``.
    """
    repo = _repo_root(args.repo_root)
    if getattr(args, "live", False):
        live_path = repo / "reports" / "last_diagnosis_live.json"
        if not live_path.is_file():
            print("No last_diagnosis_live.json - run diagnose-live first.")
            return 1
        payload = json.loads(live_path.read_text(encoding="utf-8"))
        print(payload.get("explain_paragraph") or "No explanation available.")
        print("\nEvidence:")
        for line in payload.get("primary_evidence") or []:
            print(f"- {line}")
        neg = payload.get("negative_evidence") or []
        if neg:
            print("\nNegative evidence (less likely explanations):")
            for line in neg:
                print(f"- {line}")
        return 0

    payload = _read_last_diagnosis(repo)
    sentence = payload.get("explain_sentence", "")
    print(sentence if sentence else "No explanation available.")
    print("\nEvidence:")
    for line in payload.get("selected_evidence", []):
        print(f"- {line}")
    return 0


def cmd_recommend(args: argparse.Namespace) -> int:
    """Print persisted tier buckets (diagnose / repair-safe / guided / advanced) to stdout.

    Raises:
        FileNotFoundError: When no snapshot exists.
        json.JSONDecodeError: When JSON cannot be decoded.

    Returns:
        Shell exit ``0``.
    """
    repo = _repo_root(args.repo_root)
    if getattr(args, "live", False):
        live_path = repo / "reports" / "last_diagnosis_live.json"
        if not live_path.is_file():
            print("No last_diagnosis_live.json - run diagnose-live first.")
            return 1
        payload = json.loads(live_path.read_text(encoding="utf-8"))
        blob = payload.get("recommendations") or {}
        sections = ("diagnose", "repair_safe", "guided_repair", "advanced_repair")
        for section in sections:
            print(section.upper())
            for item in blob.get(section, []):
                print(f"  [{item.get('risk')}] {item.get('title')}")
                detail = item.get("detail") or ""
                if detail:
                    print(f"      {detail}")
                script = item.get("script")
                if script:
                    print(f"      script: {script}")
            print()
        return 0

    payload = _read_last_diagnosis(repo)
    blob = payload.get("recommendations") or {}
    sections = ("diagnose", "repair_safe", "guided_repair", "advanced_repair")
    for section in sections:
        print(section.upper())
        for item in blob.get(section, []):
            print(f"  [{item.get('risk')}] {item.get('title')}")
            detail = item.get("detail") or ""
            if detail:
                print(f"      {detail}")
            script = item.get("script")
            if script:
                print(f"      script: {script}")
        print()
    return 0


def cmd_repair_safe(args: argparse.Namespace) -> int:
    """Preview safe-tier repairs; optionally launch first LOW-risk ``scripts/*.bat``.

    Side effects (``--apply`` only):
        Spawns PowerShell ``Start-Process -Verb RunAs`` for elevated batch,
        interacts on stdin for ``RUN`` and feedback prompts.

    Raises:
        None directly; subprocess errors surface as failed elevation or denied
        paths (exit codes ``1`` or ``2``).

    Audit Notes:
        Successful ``--apply`` appends interactive feedback via
        `append_feedback`; verify ``logs/decision_feedback.jsonl``.
    """
    repo = _repo_root(args.repo_root)
    if getattr(args, "live", False):
        live_path = repo / "reports" / "last_diagnosis_live.json"
        if not live_path.is_file():
            print("No last_diagnosis_live.json - run diagnose-live first.", file=sys.stderr)
            return 1
        payload = json.loads(live_path.read_text(encoding="utf-8"))
    else:
        payload = _read_last_diagnosis(repo)
    if getattr(args, "apply", False) and platform.system() != "Windows":
        print("repair-safe --apply requires Windows (elevated script launch).", file=sys.stderr)
        return 2
    safe_items = payload.get("recommendations", {}).get("repair_safe") or []

    printable = []
    runnable = []
    for item in safe_items:
        printable.append(item)
        if item.get("script") and item.get("risk") == "LOW":
            runnable.append(item)

    if not printable:
        print("No safe-tier recommendations captured in last diagnosis.")
        return 0

    print("repair-safe tier preview (nothing executed yet unless --apply was passed):")
    for item in printable:
        print(f"- [{item.get('risk')}] {item.get('title')}")
        if item.get("script"):
            print(f"    Script: {item['script']}")
        rev = item.get("reversible_notes")
        if rev:
            print(f"    Reversibility: {rev}")

    if not runnable:
        print("\nNothing executable automatically in this tier (advisory-only actions).")
        return 0

    if not getattr(args, "apply", False):
        print('\nAppend `--apply` to optionally launch the first LOW-risk *.bat script after confirming "RUN".')
        return 0

    print(
        "\nSafety policy: destructive operations and firewall resets are never launched from this CLI. "
        "Only LOW-risk scripts listed above are eligible."
    )

    diag_id = payload.get("diagnosis_id", "unknown-diagnosis-id")
    first = runnable[0]
    script_rel = Path(first["script"])
    target = (repo / script_rel).resolve()
    scripts_root = (repo / "scripts").resolve()
    try:
        target.relative_to(scripts_root)
    except ValueError:
        print("Refusing to execute script outside scripts/ directory.")
        return 2

    if not target.is_file():
        print(f"Script not found: {target}")
        return 2

    answer = input("Type RUN to execute the first LOW-risk repair script listed above: ")
    if answer.strip().upper() != "RUN":
        print("Cancelled.")
        return 1

    print(f"\nLaunching elevated batch via PowerShell.Start-Process: {target}")
    ps = (
        f"Start-Process -FilePath '{target}' "
        "-Verb RunAs -Wait"
    )
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=False)

    answer_fix = (
        input("Did that fix your issue? [y/N/unknown]: ").strip().lower() or "unknown"
    )
    if answer_fix in {"y", "yes"}:
        state: FeedbackState = "true"
    elif answer_fix in {"n", "no"}:
        state = "false"
    else:
        state = "unknown"

    user_notes = input("Optional notes (blank to skip): ").strip()
    fb = FeedbackRecord(
        diagnosis_id=diag_id,
        recommended_action=str(script_rel.as_posix()),
        user_feedback_fixed=state,
        notes=user_notes or "post-repair safe-tier feedback",
    )
    append_feedback(repo / "logs" / "decision_feedback.jsonl", fb)
    print(f"Saved feedback entry to logs\\decision_feedback.jsonl (diagnosis_id={diag_id}).")
    return 0


def cmd_feedback(args: argparse.Namespace) -> int:
    """Normalize CLI flags and append one feedback row to ``decision_feedback.jsonl``.

    Parses ``--user-feedback-fixed`` using true/false/unknown aliases documented in README.

    Raises:
        TypeError / OSError: From `append_feedback` if JSON serialization or disk write fails.

    Returns:
        Shell exit ``0``.
    """
    repo = _repo_root(args.repo_root)
    state_raw = args.user_feedback_fixed.lower()
    if state_raw in {"true", "t", "y", "yes"}:
        fb_state: FeedbackState = "true"
    elif state_raw in {"false", "f", "n", "no"}:
        fb_state = "false"
    else:
        fb_state = "unknown"

    record = FeedbackRecord(
        diagnosis_id=args.diagnosis_id,
        recommended_action=args.recommended_action,
        user_feedback_fixed=fb_state,
        notes=args.notes or "",
    )
    append_feedback(repo / "logs" / "decision_feedback.jsonl", record)
    print("Recorded feedback.")
    return 0


def cmd_proof_localhost_https(args: argparse.Namespace) -> int:
    """Run read-only localhost-proxy HTTPS causal contrast (:mod:`src.proof`)."""
    if platform.system() != "Windows":
        print(
            "proof-localhost-https uses Windows registry, netsh, netstat, and curl only.",
            file=sys.stderr,
        )
        return 2
    url = str(getattr(args, "proof_test_url", None) or "https://www.google.com")
    result = run_localhost_proxy_https_proof(test_url=url)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    return 0


def _write_live_diagnosis_report(repo: Path, payload: dict[str, Any], args: argparse.Namespace) -> int:
    """Write plaintext from ``last_diagnosis_live.json`` (v2 engine)."""
    ranked = payload.get("hypotheses_ranked") or []
    blob = payload.get("recommendations") or {}
    lines: list[str] = [
        "WINDOWS NETWORK RECOVERY TOOLKIT — LIVE DIAGNOSIS REPORT (v2)",
        f"Generated (UTC): {payload.get('generated_at_utc')}",
        f"Toolkit version : {payload.get('script_version')}",
        f"Diagnosis ID    : {payload.get('diagnosis_id')}",
        f"Snapshot file   : {payload.get('live_snapshot_ref')}",
        "",
        "SUMMARY",
        "-------",
        str(payload.get("explain_paragraph") or ""),
        "",
        "HYPOTHESES (ranked)",
        "---------------------",
    ]
    for row in ranked[:12]:
        if not isinstance(row, dict):
            continue
        lines.append(
            f"{row.get('rank', '?')}. {row.get('hypothesis')} — {float(row.get('confidence') or 0):.2f}"
        )
        for ev in row.get("evidence") or []:
            lines.append(f"   • {ev}")
    lines.extend(
        [
            "",
            "RECOMMENDED ACTIONS (tiered)",
            "-----------------------------",
            "Diagnostics:",
        ]
    )
    for item in blob.get("diagnose", []):
        if isinstance(item, dict):
            lines.append(f"  • [{item.get('risk')}] {item.get('title')}")
            if item.get("script"):
                lines.append(f"      Command/script: {item['script']}")
    lines.extend(["", "Repair-safe:"])
    for item in blob.get("repair_safe", []):
        if isinstance(item, dict):
            lines.append(f"  • [{item.get('risk')}] {item.get('title')}")
            lines.append(f"      {item.get('detail')}")
            if item.get("script"):
                lines.append(f"      Script: {item['script']}")
    lines.extend(["", "Guided repair:"])
    for item in blob.get("guided_repair", []):
        if isinstance(item, dict):
            lines.append(f"  • [{item.get('risk')}] {item.get('title')}")
            if item.get("script"):
                lines.append(f"      Script: {item['script']}")
    lines.extend(["", "Advanced repair (never auto-applied):"])
    for item in blob.get("advanced_repair", []):
        if isinstance(item, dict):
            lines.append(f"  • [{item.get('risk')}] {item.get('title')}")
            if item.get("script"):
                lines.append(f"      Script reference: {item['script']}")
    lines.extend(
        [
            "",
            "COMMANDS EXECUTED (labels only)",
            "--------------------------------",
        ]
    )
    for cmd in payload.get("commands_executed") or []:
        if isinstance(cmd, dict):
            lines.append(f"- {cmd.get('label')}: {cmd.get('cmd')}")
    lines.extend(
        [
            "",
            "NEXT STEPS",
            "----------",
            "1) Execute the safest matching recommendation first.",
            "2) Record feedback via `python -m src feedback ...` after trying a repair.",
            "3) Re-run diagnose-live to validate post-change signals.",
            "",
            "NOTICE: This report stays on-disk; upload only if your policy permits.",
        ]
    )
    report_dir = repo / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    outfile = Path(args.out) if args.out else report_dir / f"diagnosis_live_report_{ts}.txt"
    outfile.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {outfile}")
    return 0


def cmd_export_report(args: argparse.Namespace) -> int:
    """Materialize human-readable plaintext from ``last_diagnosis.json``.

    Side effects:
        Writes ``reports/diagnosis_report_<utc_ts>.txt`` unless ``--out`` given.

    Raises:
        FileNotFoundError: If no snapshot exists.
        OSError: If report path cannot be written.
    """
    repo = _repo_root(args.repo_root)
    if getattr(args, "live", False):
        live_path = repo / "reports" / "last_diagnosis_live.json"
        if not live_path.is_file():
            print("No last_diagnosis_live.json - run diagnose-live first.", file=sys.stderr)
            return 1
        payload = json.loads(live_path.read_text(encoding="utf-8"))
        return _write_live_diagnosis_report(repo, payload, args)
    payload = _read_last_diagnosis(repo)
    ranked = payload.get("ranked_root_causes") or []
    blob = payload.get("recommendations") or {}

    lines: list[str] = []
    lines.extend(
        [
            "WINDOWS NETWORK RECOVERY TOOLKIT — DIAGNOSIS REPORT",
            f"Generated (UTC): {payload.get('generated_at_utc')}",
            f"Toolkit version : {payload.get('script_version')}",
            f"Diagnosis ID    : {payload.get('diagnosis_id')}",
            "",
            "SUMMARY",
            "-------",
            payload.get("explain_sentence") or "",
            "",
            "ROOT CAUSE RANKING",
            "------------------",
        ]
    )
    for idx, item in enumerate(ranked, start=1):
        lines.append(f"{idx}. {item.get('cause')} — {float(item.get('confidence', 0)):.2f}")
        evidence = item.get("evidence") or []
        for bullet in evidence:
            lines.append(f"   • {bullet}")
    lines.extend(
        [
            "",
            "SELECTED HYPOTHESIS",
            "-------------------",
            f"Cause       : {payload.get('selected_root_cause')}",
            f"Confidence  : {float(payload.get('selected_confidence') or 0):.2f}",
            "",
            "EVIDENCE",
            "--------",
        ]
    )
    for bullet in payload.get("selected_evidence") or []:
        lines.append(f"- {bullet}")
    lines.extend(
        [
            "",
            "RECOMMENDED ACTIONS (tiered)",
            "-----------------------------",
            "Modes: diagnose (read-only), repair-safe (reversible/low risk), ",
            "guided repair (confirmation in batch wrappers), ",
            "advanced repair (destructive/policy sensitive — manual only).",
            "",
            "Diagnostics:",
        ]
    )
    for item in blob.get("diagnose", []):
        lines.append(f"  • [{item.get('risk')}] {item.get('title')}")
        if item.get("script"):
            lines.append(f"      Command/script: {item['script']}")
    lines.extend(["", "Repair-safe:"])
    for item in blob.get("repair_safe", []):
        lines.append(f"  • [{item.get('risk')}] {item.get('title')}")
        lines.append(f"      {item.get('detail')}")
        if item.get("script"):
            lines.append(f"      Script: {item['script']}")
        lines.append(f"      Risk: {item.get('risk')} — {item.get('reversible_notes')}")
    lines.extend(["", "Guided repair:"])
    for item in blob.get("guided_repair", []):
        lines.append(f"  • [{item.get('risk')}] {item.get('title')}")
        if item.get("script"):
            lines.append(f"      Script: {item['script']}")
    lines.extend(["", "Advanced repair (never auto-applied):"])
    for item in blob.get("advanced_repair", []):
        lines.append(f"  • [{item.get('risk')}] {item.get('title')}")
        if item.get("script"):
            lines.append(f"      Script reference: {item['script']}")
    lines.extend(
        [
            "",
            "COMMANDS EXECUTED (labels only)",
            "--------------------------------",
        ]
    )
    for cmd in payload.get("commands_executed") or []:
        lines.append(f"- {cmd.get('label')}: {cmd.get('cmd')}")
    lines.extend(
        [
            "",
            "NEXT STEPS",
            "----------",
            "1) Execute the safest matching recommendation first.",
            "2) Record feedback via `python -m src feedback ...` after trying a repair.",
            "3) Re-run diagnose to validate post-change signals.",
            "",
            "NOTICE: This report stays on-disk; upload only if your policy permits.",
        ]
    )

    report_dir = repo / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    outfile = Path(args.out) if args.out else report_dir / f"diagnosis_report_{ts}.txt"
    outfile.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {outfile}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Configure argparse for ``python -m src`` dispatch.

    Returns:
        Root parser with mutually exclusive subcommands that map 1:1 to README workflows.

    Raises:
        None.
    """
    parser = argparse.ArgumentParser(
        prog="python -m src",
        description="Decision architecture CLI for Windows network diagnostics.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Explicit repository root (defaults to toolkit checkout).",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_diag = sub.add_parser(
        "diagnose",
        help="Diagnose connectivity: legacy v1 scoring, or live v2 via --live / --proof.",
        description=(
            "Default (no flags): collects signals, applies v1 root-cause scores, writes "
            "`reports/last_diagnosis.json`, appends `logs/decision_audit.jsonl`. "
            "`--live`: same snapshot + v2 engine as `diagnose-live`. "
            "`--proof`: live run plus Proof Engine (HTTPS localhost-proxy contrast). "
            "With `--live`/`--proof`, `--json` streams JSON-only (API-friendly); "
            "`--both` adds a human preamble before JSON_PAYLOAD delimiters."
        ),
    )
    p_diag.add_argument(
        "--fixture",
        type=str,
        default=None,
        help="Load features JSON instead of probing (legacy v1 only; incompatible with --live/--proof).",
    )
    p_diag.add_argument(
        "--live",
        dest="live_engine",
        action="store_true",
        help="Run live v2 diagnosis (snapshot + hypotheses + policy); alias of `diagnose-live`.",
    )
    p_diag.add_argument(
        "--proof",
        dest="proof_engine",
        action="store_true",
        help="Live v2 with Proof Engine enabled (implies --live).",
    )
    p_diag.add_argument(
        "--json",
        action="store_true",
        help=(
            "Legacy v1: append JSON payload after human text (JSON_PAYLOAD_* delimiters). "
            "Live (`--live`/`--proof`): JSON only on stdout — same behavior as `diagnose-live --json`."
        ),
    )
    p_diag.add_argument(
        "--both",
        dest="both_formats",
        action="store_true",
        help="With --live/--proof only: explainable prose, then JSON block (exclusive with --json).",
    )
    p_diag.add_argument(
        "--app",
        type=str,
        default=None,
        metavar="APP",
        help="App-path scenario diagnosis (e.g. chatgpt). Incompatible with --live/--proof.",
    )
    p_diag.add_argument(
        "--recovery-feedback",
        type=str,
        default=None,
        dest="recovery_feedback",
        metavar="HINT",
        help="Post-recovery hint for verification, e.g. firewall_reset_helped.",
    )
    p_diag.set_defaults(func=cmd_diagnose, live_engine=False, proof_engine=False, both_formats=False)

    p_exp_sub = sub.add_parser("explain", help="Print rationale for last diagnose or diagnose-live.")
    p_exp_sub.add_argument(
        "--live",
        action="store_true",
        help="Use reports/last_diagnosis_live.json (diagnose-live) instead of last_diagnosis.json.",
    )
    p_exp_sub.set_defaults(func=cmd_explain)

    p_rec_sub = sub.add_parser("recommend", help="Show tiered recommendations from last diagnose run.")
    p_rec_sub.add_argument(
        "--live",
        action="store_true",
        help="Use live v2 recommendations from last_diagnosis_live.json.",
    )
    p_rec_sub.set_defaults(func=cmd_recommend)

    p_safe = sub.add_parser(
        "repair-safe",
        help="Preview safe-tier fixes from the last diagnose run.",
    )
    p_safe.add_argument(
        "--live",
        action="store_true",
        help="Use reports/last_diagnosis_live.json (diagnose-live) instead of last_diagnosis.json.",
    )
    p_safe.add_argument(
        "--apply",
        action="store_true",
        help="Prompt to launch the first LOW-risk *.bat recommendation (otherwise preview only).",
    )
    p_safe.set_defaults(func=cmd_repair_safe)

    p_fb = sub.add_parser("feedback", help="Persist structured outcome feedback tied to diagnosis_id.")
    p_fb.add_argument("--diagnosis-id", required=True, dest="diagnosis_id")
    p_fb.add_argument("--recommended-action", required=True, dest="recommended_action")
    p_fb.add_argument("--user-feedback-fixed", required=True, dest="user_feedback_fixed")
    p_fb.add_argument("--notes", default="", dest="notes")
    p_fb.set_defaults(func=cmd_feedback)

    p_exp = sub.add_parser("export-report", help="Render a plaintext report under reports/.")
    p_exp.add_argument(
        "--live",
        action="store_true",
        help="Use reports/last_diagnosis_live.json (diagnose-live) instead of last_diagnosis.json.",
    )
    p_exp.add_argument("--out", type=str, default=None, help="Custom output filename.")
    p_exp.set_defaults(func=cmd_export_report)

    p_ps = sub.add_parser("proxy-status", help="Show HKCU WinINET proxy keys with parsed mode.")
    p_ps.add_argument("--json", dest="emit_json", action="store_true", help="Print merged JSON mapping.")
    p_ps.set_defaults(func=cmd_proxy_status)

    p_ppath = sub.add_parser(
        "proxy-path-status",
        help="Registry vs operational proxy path (listener + optional HTTPS proxied/bypass contrast).",
    )
    p_ppath.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_ppath.add_argument(
        "--no-https-contrast",
        action="store_true",
        help="Skip curl proxied/bypass contrast (listener + registry only).",
    )
    p_ppath.add_argument(
        "--test-url",
        type=str,
        default="https://www.google.com",
        help="HTTPS URL for contrast probes (default https://www.google.com).",
    )
    p_ppath.set_defaults(func=cmd_proxy_path_status)

    p_po = sub.add_parser("proxy-owner", help="Resolve netstat listener owners for localhost proxy port.")
    p_po.add_argument("--port", type=int, default=None, help="Override port (defaults to parsed ProxyServer).")
    p_po.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON attribution block.")
    p_po.set_defaults(func=cmd_proxy_owner)

    p_psl = sub.add_parser(
        "proxy-stop-listener",
        help="Preview/apply scoped taskkill for attributed localhost proxy listener (typed confirm, Admin).",
    )
    _add_proxy_stop_listener_arguments(p_psl)
    p_psl.set_defaults(func=cmd_proxy_stop_listener, stop_listener_first=False, stop_reverter_first=False)

    p_psr = sub.add_parser(
        "proxy-stop-reverter",
        help="Preview/apply scoped taskkill for attributed proxy reverter parent (typed confirm, Admin).",
    )
    _add_proxy_stop_reverter_arguments(p_psr)
    p_psr.set_defaults(func=cmd_proxy_stop_reverter, stop_reverter_first=False)

    p_pm = sub.add_parser("proxy-monitor", help="Poll HKCU proxy registry for changes (read-only).")
    p_pm.add_argument("--interval", type=float, default=5.0, help="Seconds between polls (default 5).")
    p_pm.add_argument("--once", action="store_true", help="Single poll then exit.")
    p_pm.add_argument(
        "--jsonl",
        type=str,
        default=None,
        help="Append JSONL events to this path (e.g. logs/proxy_guard_events.jsonl).",
    )
    p_pm.set_defaults(func=cmd_proxy_monitor)

    p_pxw = sub.add_parser(
        "proxy-watch",
        help="Poll WinINET HKCU state, diff, attribute processes, append logs/proxy_guard.jsonl (no silent rollback).",
    )
    p_pxw.add_argument("--interval", type=float, default=5.0, help="Seconds between polls (default 5).")
    p_pxw.add_argument("--once", action="store_true", help="Poll twice (detect first change if any) then exit.")
    p_pxw.add_argument(
        "--soak-minutes",
        type=float,
        default=0.0,
        dest="soak_minutes",
        help="Short soak: poll for N minutes then exit with watch_soak_result (0=unbounded). Use 2 for rewrite checks.",
    )
    p_pxw.add_argument(
        "--exit-on-rewrite",
        dest="exit_on_rewrite",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="During soak, exit early when ProxyEnable flips 0→1 (default: true). Use --no-exit-on-rewrite to run full window.",
    )
    p_pxw.add_argument(
        "--evidence-csv",
        type=str,
        default=None,
        dest="proxy_watch_evidence_csv",
        metavar="PATH",
        help="Optional Procmon CSV export (Internet Settings path rows) to modestly boost attribution confidence.",
    )
    p_pxw.add_argument(
        "--final-causation",
        dest="proxy_watch_final_causation",
        action="store_true",
        help="On drift, run final causation collector (best-effort; does not require Sysmon).",
    )
    p_pxw.set_defaults(func=cmd_proxy_watch)

    p_pmf = sub.add_parser(
        "procmon-filter-set",
        help="Print or export Procmon Include filters for WinINET proxy RegSetValue writer capture.",
    )
    p_pmf.add_argument("--json", dest="emit_json", action="store_true", help="Emit machine-readable filter set JSON.")
    p_pmf.add_argument(
        "--export",
        dest="procmon_filter_export",
        metavar="PATH",
        default=None,
        help="Write filter set JSON to PATH (creates parents).",
    )
    p_pmf.set_defaults(func=cmd_procmon_filter_set)

    p_pxw = sub.add_parser(
        "proxy-watch-report",
        help="Human-readable report for reports/proxy_guard_watch.jsonl (Windows).",
    )
    p_pxw.add_argument("--tail", type=int, default=10, dest="proxy_watch_tail", help="Last N events (default 10).")
    p_pxw.add_argument("--json", dest="emit_json", action="store_true", help="Emit raw JSON instead of text.")
    p_pxw.set_defaults(func=cmd_proxy_watch_report)

    p_pg = sub.add_parser(
        "proxy-guard",
        help="Policy-aware proxy monitor with optional WinINET/WinHTTP rollback (Windows).",
    )
    p_pg.add_argument("--interval", type=float, default=5.0, help="Seconds between polls (default 5).")
    p_pg.add_argument("--once", action="store_true", help="Single poll then exit (initial baseline snapshot).")
    p_pg.add_argument(
        "--auto-rollback",
        action="store_true",
        help="On blocked changes, restore prior HKCU/WinHTTP snapshot via reg/netsh (still respects dry-run gates).",
    )
    p_pg.add_argument(
        "--rollback",
        action="store_true",
        dest="cli_rollback",
        help="Enable rollback planning/execution like --auto-rollback; live HKCU writes require --rollback-confirm RESTORE_PROXY unless using --auto-rollback alone.",
    )
    p_pg.add_argument(
        "--rollback-confirm",
        type=str,
        default="",
        dest="rollback_confirm_phrase",
        metavar="PHRASE",
        help='When using --rollback (not --auto-rollback), live restore requires phrase "RESTORE_PROXY".',
    )
    p_pg.add_argument(
        "--policy",
        type=str,
        default=None,
        help="JSON policy file (defaults to shared/proxy_guard_policy.example.json under repo root).",
    )
    p_pg.add_argument(
        "--jsonl",
        type=str,
        default=None,
        help="Append control-plane JSONL (default logs/proxy_guard_control.jsonl).",
    )
    p_pg.add_argument(
        "--dry-run-rollback",
        action="store_true",
        help="Log rollback commands without executing reg/netsh (testing).",
    )
    p_pg.add_argument(
        "--config",
        type=str,
        default=None,
        dest="service_config",
        help="Optional JSON service config (probe retries, rollback cooldown — see docs/proxy_guard.md).",
    )
    p_pg.add_argument(
        "--structured-log",
        type=str,
        default=None,
        dest="structured_log",
        help="Append JSON-lines operational log (same schema as stderr; optional file sink).",
    )
    p_pg.add_argument(
        "--dry-run",
        action="store_true",
        dest="proxy_guard_dry_run",
        help="Prevent live HKCU / WinHTTP restore even when auto-rollback is enabled (audit + dry commands only).",
    )
    p_pg.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        help="Print machine JSON on each change instead of human-readable text.",
    )
    p_pg.add_argument(
        "--trust-current",
        action="store_true",
        dest="trust_current_lkg",
        help="Persist the first captured snapshot under reports/proxy_guard_lkg.json as last-known-good.",
    )
    p_pg.add_argument(
        "--show-lkg",
        action="store_true",
        dest="show_lkg",
        help="Print reports/proxy_guard_lkg.json and exit.",
    )
    p_pg.add_argument(
        "--clear-lkg",
        action="store_true",
        dest="clear_lkg",
        help="Remove reports/proxy_guard_lkg.json and exit.",
    )
    p_pg.add_argument(
        "--attribution-mode",
        choices=("auto", "best-effort", "eventlog"),
        default="auto",
        help="Prefer Sysmon EventID 13 (auto/eventlog) or skip to listen-owner heuristics (best-effort).",
    )
    p_pg.add_argument(
        "--restore-git-npm-env",
        action="store_true",
        dest="restore_git_npm_env",
        help="Reserved — currently guarded off inside rollback until an explicit confirmation story exists.",
    )
    p_pg.add_argument(
        "--known-good",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "On rollback, restore this named snapshot: prefer logs/network_state_snapshots.jsonl "
            "(Network State Manager), else logs/proxy_known_good_snapshots.jsonl (HKCU/Git/npm/env/WinHTTP)."
        ),
    )
    p_pg.add_argument(
        "--evidence-csv",
        type=str,
        default=None,
        dest="proxy_guard_evidence_csv",
        metavar="PATH",
        help="Optional Procmon CSV export (RegSetValue on Internet Settings proxy keys) for layered attribution.",
    )
    p_pg.add_argument(
        "--attribution-window",
        type=int,
        default=90,
        dest="proxy_guard_attribution_seconds",
        metavar="SECONDS",
        help="Sysmon Event 13 / rough Procmon time gate in seconds (default 90; minimum 60 in config clamp).",
    )
    p_pg.set_defaults(func=cmd_proxy_guard)

    p_pss = sub.add_parser(
        "proxy-snapshot",
        help="Named last-known-good proxy snapshots (capture, compare, restore allowlisted surfaces).",
    )
    p_pss_sub = p_pss.add_subparsers(dest="proxy_snapshot_cmd", required=True)

    p_pss_sv = p_pss_sub.add_parser(
        "save",
        help="Capture HKCU WinINET, WinHTTP, Git, npm, and user proxy env into logs/proxy_known_good_snapshots.jsonl.",
    )
    p_pss_sv.add_argument("--name", required=True, dest="snapshot_name", metavar="NAME", help="Snapshot label.")
    p_pss_sv.add_argument(
        "--as-default",
        action="store_true",
        help="Also write config/last_known_good_proxy.json pointing at this snapshot.",
    )
    p_pss_sv.set_defaults(func=cmd_proxy_snapshot_save)

    p_pss_ls = p_pss_sub.add_parser("list", help="List snapshot names from JSONL plus default-config flag.")
    p_pss_ls.set_defaults(func=cmd_proxy_snapshot_list)

    p_pss_sh = p_pss_sub.add_parser("show", help="Print the latest JSONL record for --name.")
    p_pss_sh.add_argument("--name", required=True, dest="snapshot_name", metavar="NAME")
    p_pss_sh.set_defaults(func=cmd_proxy_snapshot_show)

    p_pss_df = p_pss_sub.add_parser("diff", help="Compare current machine state vs saved snapshot (changed fields only).")
    p_pss_df.add_argument("--name", required=True, dest="snapshot_name", metavar="NAME")
    p_pss_df.set_defaults(func=cmd_proxy_snapshot_diff)

    p_pss_rs = p_pss_sub.add_parser(
        "restore",
        help="Restore allowlisted proxy settings from snapshot (dry-run unless --confirm RESTORE_KNOWN_GOOD_PROXY).",
    )
    p_pss_rs.add_argument("--name", required=True, dest="snapshot_name", metavar="NAME")
    p_pss_rs.add_argument("--dry-run", action="store_true", help="Force preview only even if confirm phrase is set.")
    p_pss_rs.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help='Live restore requires exact phrase RESTORE_KNOWN_GOOD_PROXY; omit for dry-run preview only.',
    )
    p_pss_rs.set_defaults(func=cmd_proxy_snapshot_restore)

    p_pxlinux = sub.add_parser(
        "proxy-linux-snapshot",
        help="Read-only Linux proxy snapshot (env, /etc/environment, gsettings, NM, apt).",
    )
    p_pxlinux.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_pxlinux.add_argument(
        "--skip-optional-cli",
        dest="skip_optional_cli",
        action="store_true",
        help="Skip gsettings/nmcli probes (faster; env and file reads only).",
    )
    p_pxlinux.set_defaults(func=cmd_proxy_linux_snapshot)

    p_pxdiag = sub.add_parser(
        "proxy-diagnose",
        help="WinINET-focused diagnose with FailureBlocks and optional localhost listener attribution.",
    )
    p_pxdiag.add_argument("--json", dest="emit_json", action="store_true", help="Emit machine-readable JSON.")
    p_pxdiag.add_argument(
        "--skip-listener-probe",
        action="store_true",
        help="Skip netstat/tasklist attribution (offline / faster CI).",
    )
    p_pxdiag.set_defaults(func=cmd_proxy_diagnose)

    p_pxin = sub.add_parser(
        "proxy-investigate",
        help="Read-only unified proxy investigation (OBSERVED/CORRELATED/NOT PROVEN; no mutations).",
    )
    p_pxin.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_pxin.add_argument(
        "--since",
        dest="investigate_since",
        default="30m",
        metavar="DURATION",
        help="Look-back for proxy-watch transitions and Sysmon window (e.g. 30m, 2h, 3600).",
    )
    p_pxin.add_argument(
        "--procmon",
        dest="investigate_procmon",
        default=None,
        metavar="CSV",
        help="Optional Procmon CSV export for registry writer proof tier.",
    )
    p_pxin.add_argument(
        "--audit",
        dest="investigate_audit",
        action="store_true",
        help="Append one read-only investigation row to logs/repair_audit.jsonl.",
    )
    p_pxin.add_argument(
        "--no-audit",
        dest="investigate_no_audit",
        action="store_true",
        help="Do not write audit rows (default unless --audit).",
    )
    p_pxin.set_defaults(func=cmd_proxy_investigate, investigate_audit=False, investigate_no_audit=False)

    p_pxfore = sub.add_parser(
        "proxy-forensics",
        help="Sysmon Event ID 13 registry-write causation for proxy-watch transitions (read-only).",
    )
    p_pxfore.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_pxfore.add_argument(
        "--since-minutes",
        type=int,
        default=None,
        dest="forensics_since_minutes",
        help="Analyze proxy-watch JSONL transitions from the last N minutes (default 30).",
    )
    p_pxfore.add_argument(
        "--around",
        dest="forensics_around",
        default=None,
        metavar="ISO8601",
        help='Anchor UTC timestamp for windowed forensics (e.g. "2026-06-08T05:00:55Z").',
    )
    p_pxfore.add_argument(
        "--window-seconds",
        type=int,
        default=10,
        dest="forensics_window_seconds",
        help="±seconds around each transition for Sysmon query (default 10).",
    )
    p_pxfore.add_argument(
        "--watch-integrated",
        dest="forensics_watch_integrated",
        action="store_true",
        help="Load transitions from logs/proxy_guard.jsonl (same sink as proxy-watch).",
    )
    p_pxfore.set_defaults(func=cmd_proxy_forensics)

    p_pxcaus = sub.add_parser(
        "proxy-causation",
        help="Final causation report: registry writer proof, port owner, path proof (read-only).",
    )
    p_pxcaus.add_argument(
        "--since-minutes",
        type=int,
        default=30,
        dest="proxy_causation_since_minutes",
        help="Look-back window for Sysmon and proxy-watch transitions (default 30).",
    )
    p_pxcaus.add_argument(
        "--watch",
        dest="proxy_causation_watch",
        action="store_true",
        help="Integrate with proxy-watch loop and run final causation on each drift.",
    )
    p_pxcaus.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Poll interval when --watch is set (default 5).",
    )
    p_pxcaus.add_argument(
        "--once",
        action="store_true",
        help="Single poll when --watch is set.",
    )
    p_pxcaus.add_argument(
        "--export",
        dest="proxy_causation_export",
        default=None,
        metavar="PATH",
        help="Write JSON report to path (e.g. reports/proxy_causation.json).",
    )
    p_pxcaus.add_argument(
        "--format",
        dest="proxy_causation_format",
        choices=["text", "markdown", "json"],
        default="markdown",
        help="Output format (default markdown).",
    )
    p_pxcaus.add_argument(
        "--fixture",
        dest="proxy_causation_fixture",
        default=None,
        metavar="DIR",
        help="Fixture scenario directory (CI/offline; skips live Windows probes).",
    )
    p_pxcaus.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON to stdout.")
    p_pxcaus.set_defaults(func=cmd_proxy_causation)

    p_pxcls = sub.add_parser(
        "proxy-classify",
        help="Classify registry writer for latest proxy-watch transition (read-only).",
    )
    p_pxcls.add_argument("--json", dest="emit_json", action="store_true")
    p_pxcls.add_argument("--latest", action="store_true", default=True, help=argparse.SUPPRESS)
    p_pxcls.set_defaults(func=cmd_proxy_classify)

    p_pxpol = sub.add_parser(
        "proxy-policy",
        help="Policy decision for latest proxy-watch transition (read-only).",
    )
    p_pxpol.add_argument("--json", dest="emit_json", action="store_true")
    p_pxpol.add_argument("--latest", action="store_true", default=True, help=argparse.SUPPRESS)
    p_pxpol.add_argument("--input", dest="policy_input", metavar="JSONL", help="proxy-watch audit JSONL path.")
    p_pxpol.add_argument("--fixture", dest="policy_fixture", metavar="JSON", help="Incident fixture JSON (portable demo).")
    p_pxpol.add_argument(
        "--format",
        dest="policy_format",
        choices=("text", "json"),
        default="text",
        help="Output format (default text).",
    )
    p_pxpol.add_argument(
        "--policy",
        dest="policy_yaml",
        metavar="YAML",
        help="Policy-as-code YAML profile (config/policies/*.yaml).",
    )
    p_pxpol.set_defaults(func=cmd_proxy_policy)

    p_pxtl = sub.add_parser(
        "proxy-timeline",
        help="Replay proxy incident timeline from audit + Sysmon (read-only).",
    )
    p_pxtl.add_argument(
        "--since-minutes",
        type=int,
        default=60,
        dest="timeline_since_minutes",
        help="Look-back window for transitions (default 60).",
    )
    p_pxtl.add_argument(
        "--format",
        dest="timeline_format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Output format (default text).",
    )
    p_pxtl.add_argument(
        "--fixture",
        dest="timeline_fixture",
        metavar="JSON",
        help="Replay timeline from incident fixture (works on Linux CI).",
    )
    p_pxtl.add_argument(
        "--around",
        dest="timeline_around",
        metavar="ISO8601",
        help='Anchor UTC timestamp (e.g. "2026-06-08T05:00:55Z").',
    )
    p_pxtl.add_argument(
        "--window-seconds",
        type=int,
        default=30,
        dest="timeline_window_seconds",
        help="±seconds when using --around (default 30).",
    )
    p_pxtl.set_defaults(func=cmd_proxy_timeline)

    p_pxrep = sub.add_parser(
        "proxy-report",
        help="Incident evidence report (default) or JSONL tail summary with --tail.",
    )
    p_pxrep.add_argument("--latest", action="store_true", default=True, help=argparse.SUPPRESS)
    p_pxrep.add_argument(
        "--tail",
        type=int,
        default=None,
        dest="proxy_report_tail",
        help="Legacy mode: summarize last N rows from logs/proxy_guard.jsonl.",
    )
    p_pxrep.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON (both modes).")
    p_pxrep.add_argument(
        "--fixture",
        dest="report_fixture",
        metavar="JSON",
        help="Incident fixture JSON for portable evidence-tree demo (Linux CI safe).",
    )
    p_pxrep.add_argument(
        "--format",
        dest="report_format",
        choices=("text", "json", "markdown"),
        default="text",
        help="Incident report output format (default text; ignored with --tail).",
    )
    p_pxrep.set_defaults(func=cmd_proxy_report)

    p_pxattr = sub.add_parser(
        "proxy-attribution",
        help="Structured localhost proxy listener attribution (netstat + tasklist + CIM).",
    )
    p_pxattr.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON only.")
    p_pxattr.add_argument("--port", type=int, default=None, help="Override proxy port parsing.")
    p_pxattr.add_argument(
        "--procmon",
        dest="procmon_csv",
        default=None,
        metavar="CSV",
        help="Parse Procmon CSV for RegSetValue on Internet Settings proxy keys (proof tier).",
    )
    p_pxattr.set_defaults(func=cmd_proxy_attribution)

    p_pxrb = sub.add_parser(
        "proxy-rollback",
        help="Restore HKCU WinINET from snapshots JSONL (--snapshot-id) or a known-good JSON file (--from-snapshot).",
    )
    g_rb = p_pxrb.add_mutually_exclusive_group(required=True)
    g_rb.add_argument("--snapshot-id", dest="snapshot_id", metavar="ID", help="UUID from logs/proxy_snapshots.jsonl.")
    g_rb.add_argument(
        "--from-snapshot",
        type=str,
        dest="rollback_from_snapshot",
        metavar="PATH",
        help="Path to known-good JSON ({\"snapshot\":{...}} or flat ProxySnapshot dict). Live apply needs --confirm RESTORE_PROXY_SNAPSHOT_FILE.",
    )
    p_pxrb.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="rollback_file_confirm_phrase",
        metavar="PHRASE",
        help="With --from-snapshot: typed phrase RESTORE_PROXY_SNAPSHOT_FILE enables live restore (omit for preview).",
    )
    p_pxrb.add_argument("--dry-run", action="store_true", help="Show argv preview only.")
    p_pxrb.set_defaults(snapshot_id=None, func=cmd_proxy_rollback)

    p_pd = sub.add_parser("proxy-disable", help="Preview/apply safe HKCU WinINET proxy disable (typed confirm).")
    p_pd.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        help="Preview only by default. Use --dry-run false with --confirm DISABLE_WININET_PROXY to apply.",
    )
    p_pd.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live apply requires exact phrase DISABLE_WININET_PROXY.",
    )
    p_pd.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_pd.add_argument(
        "--no-clear-server",
        action="store_false",
        dest="clear_server",
        help="Only set ProxyEnable=0; leave ProxyServer (not recommended).",
    )
    p_pd.add_argument(
        "--no-clear-autoconfig",
        action="store_false",
        dest="clear_autoconfig",
        help="Do not delete AutoConfigURL.",
    )
    p_pd.add_argument(
        "--soak-minutes",
        type=float,
        default=0.0,
        help="After apply, poll ProxyEnable for N minutes; 0 skips. Use 15 for sticky check.",
    )
    p_pd.add_argument(
        "--soak-poll-seconds",
        type=float,
        default=5.0,
        help="Soak poll interval (default 5).",
    )
    p_pd.add_argument(
        "--stop-listener-first",
        action="store_true",
        help="Before disable apply, run stop-listener (requires --stop-listener-confirm STOP_PROXY_LISTENER).",
    )
    p_pd.add_argument(
        "--stop-listener-confirm",
        type=str,
        default="",
        dest="stop_listener_confirm_phrase",
        metavar="PHRASE",
        help="Typed phrase STOP_PROXY_LISTENER when using --stop-listener-first on live apply.",
    )
    _add_proxy_stop_reverter_arguments(p_pd, include_chained=True)
    p_pd.set_defaults(
        func=cmd_proxy_disable,
        clear_server=True,
        clear_autoconfig=True,
        stop_listener_first=False,
        stop_reverter_first=False,
        stop_parent_tree=False,
    )

    p_si = sub.add_parser(
        "startup-inventory",
        help="Targeted Windows startup inventory (no full profile recursion).",
    )
    p_si.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON only.")
    p_si.set_defaults(func=cmd_startup_inventory)

    p_pbt = sub.add_parser(
        "proxy-boot-trace",
        help="Post-login WinINET/WinHTTP/listener trace with delta detection.",
    )
    p_pbt.add_argument("--duration", type=float, default=180.0, dest="boot_trace_duration")
    p_pbt.add_argument("--interval", type=float, default=2.0, dest="boot_trace_interval")
    p_pbt.add_argument("--json", dest="emit_json", action="store_true")
    p_pbt.set_defaults(func=cmd_proxy_boot_trace)

    p_ibtt = sub.add_parser(
        "install-boot-trace-task",
        help="Preview/install WNRT-ProxyBootTrace logon scheduled task.",
    )
    p_ibtt.add_argument("--duration", type=int, default=180, dest="boot_trace_duration")
    p_ibtt.add_argument("--interval", type=int, default=2, dest="boot_trace_interval")
    p_ibtt.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        dest="dry_run",
        help="Preview only by default. Use --dry-run false with --confirm INSTALL_BOOT_TRACE_TASK.",
    )
    p_ibtt.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live install requires INSTALL_BOOT_TRACE_TASK.",
    )
    p_ibtt.add_argument("--json", dest="emit_json", action="store_true")
    p_ibtt.set_defaults(func=cmd_install_boot_trace_task)

    p_ubtt = sub.add_parser(
        "uninstall-boot-trace-task",
        help="Preview/uninstall WNRT-ProxyBootTrace logon scheduled task.",
    )
    p_ubtt.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        dest="dry_run",
        help="Preview only by default. Use --dry-run false with --confirm UNINSTALL_BOOT_TRACE_TASK.",
    )
    p_ubtt.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live uninstall requires UNINSTALL_BOOT_TRACE_TASK.",
    )
    p_ubtt.add_argument("--json", dest="emit_json", action="store_true")
    p_ubtt.set_defaults(func=cmd_uninstall_boot_trace_task)

    p_iso = sub.add_parser(
        "install-startup-observability",
        help="Preview/install guardian + boot trace startup observability.",
    )
    p_iso.add_argument("--guardian-interval", type=int, default=15, dest="guardian_interval")
    p_iso.add_argument("--duration", type=int, default=180, dest="boot_trace_duration")
    p_iso.add_argument("--interval", type=int, default=2, dest="boot_trace_interval")
    p_iso.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        dest="dry_run",
        help="Preview only by default. Use --dry-run false with --confirm INSTALL_STARTUP_OBSERVABILITY.",
    )
    p_iso.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live install requires INSTALL_STARTUP_OBSERVABILITY.",
    )
    p_iso.add_argument("--json", dest="emit_json", action="store_true")
    p_iso.set_defaults(func=cmd_install_startup_observability)

    p_uso = sub.add_parser(
        "uninstall-startup-observability",
        help="Preview/uninstall guardian + boot trace startup observability.",
    )
    p_uso.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        dest="dry_run",
        help="Preview only by default. Use --dry-run false with --confirm UNINSTALL_STARTUP_OBSERVABILITY.",
    )
    p_uso.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live uninstall requires UNINSTALL_STARTUP_OBSERVABILITY.",
    )
    p_uso.add_argument("--json", dest="emit_json", action="store_true")
    p_uso.set_defaults(func=cmd_uninstall_startup_observability)

    p_pgd = sub.add_parser(
        "proxy-guardian",
        help="Dead localhost WinINET proxy guardian (dry-run by default; distinct from proxy-guard).",
    )
    p_pgd.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        dest="dry_run",
        help="Preview only by default. Use --dry-run false with --confirm CLEAR_DEAD_LOCALHOST_PROXY.",
    )
    p_pgd.add_argument("--once", action="store_true", help="Single check then exit (default).")
    p_pgd.add_argument(
        "--loop",
        action="store_true",
        dest="guardian_loop",
        help="Repeat every --interval seconds until interrupted.",
    )
    p_pgd.add_argument("--interval", type=float, default=60.0, help="Seconds between checks when --loop.")
    p_pgd.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live dead-proxy clear requires CLEAR_DEAD_LOCALHOST_PROXY.",
    )
    p_pgd.add_argument(
        "--clear-broken",
        action="store_true",
        dest="clear_broken",
        help="Also detect active-but-broken (listener up, path fail, direct ok).",
    )
    p_pgd.add_argument(
        "--confirm-broken",
        type=str,
        default="",
        dest="confirm_broken",
        metavar="PHRASE",
        help="Live broken/hold-direct clear requires PREFER_DIRECT_WININET.",
    )
    p_pgd.add_argument(
        "--hold-direct",
        action="store_true",
        dest="hold_direct",
        help=(
            "Clear ANY enabled localhost WinINET proxy (including healthy tunnels) "
            "using --confirm-broken PREFER_DIRECT_WININET. For LinkedIn-style rewrite recurrence."
        ),
    )
    p_pgd.add_argument("--json", dest="emit_json", action="store_true")
    p_pgd.set_defaults(func=cmd_proxy_guardian_drift, once=True)

    p_igt = sub.add_parser(
        "install-guardian-task",
        help="Preview/install WNRT-DeadProxyGuardian logon scheduled task.",
    )
    p_igt.add_argument("--interval", type=int, default=60)
    p_igt.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        dest="dry_run",
    )
    p_igt.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live install requires INSTALL_GUARDIAN_TASK.",
    )
    p_igt.add_argument("--json", dest="emit_json", action="store_true")
    p_igt.set_defaults(func=cmd_install_guardian_task)

    p_ugt = sub.add_parser(
        "uninstall-guardian-task",
        help="Preview/remove WNRT-DeadProxyGuardian scheduled task.",
    )
    p_ugt.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        dest="dry_run",
    )
    p_ugt.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live uninstall requires UNINSTALL_GUARDIAN_TASK.",
    )
    p_ugt.add_argument("--json", dest="emit_json", action="store_true")
    p_ugt.set_defaults(func=cmd_uninstall_guardian_task)

    p_pfx = sub.add_parser(
        "proxy-fix",
        help="Emergency HKCU WinINET fix — clears localhost ProxyServer only.",
    )
    p_pfx.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        dest="dry_run",
    )
    p_pfx.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live apply requires DISABLE_WININET_PROXY.",
    )
    p_pfx.add_argument(
        "--clear-pac",
        action="store_true",
        dest="clear_pac",
        help="Also clear AutoConfigURL (requires --confirm CLEAR_PAC_TOO).",
    )
    p_pfx.add_argument("--json", dest="emit_json", action="store_true")
    p_pfx.set_defaults(func=cmd_proxy_fix)

    p_ss = sub.add_parser(
        "safe-search",
        help="Timeout-safe targeted file search (no full profile recursion).",
    )
    p_ss.add_argument("--query", required=True, dest="search_query")
    p_ss.add_argument(
        "--target",
        default="project",
        dest="search_target",
        choices=("project", "startup", "logs", "scripts"),
    )
    p_ss.add_argument("--max-seconds", type=float, default=20.0, dest="search_max_seconds")
    p_ss.add_argument("--max-files", type=int, default=3000, dest="search_max_files")
    p_ss.add_argument("--json", dest="emit_json", action="store_true")
    p_ss.set_defaults(func=cmd_safe_search)

    p_ceb = sub.add_parser(
        "collect-evidence-bundle",
        help="Collect a read-only proxy/network evidence bundle under reports/.",
    )
    p_ceb.add_argument("--out-dir", dest="bundle_dir", default=None)
    p_ceb.add_argument("--duration", type=int, default=30, dest="boot_trace_duration")
    p_ceb.add_argument("--interval", type=int, default=2, dest="boot_trace_interval")
    p_ceb.add_argument("--json", dest="emit_json", action="store_true")
    p_ceb.set_defaults(func=cmd_collect_evidence_bundle)

    p_sor = sub.add_parser(
        "startup-observability-report",
        help="Summarize boot trace JSONL into an operator-readable report.",
    )
    p_sor.add_argument("--trace-path", dest="trace_path", default="")
    p_sor.add_argument("--json", dest="emit_json", action="store_true")
    p_sor.set_defaults(func=cmd_startup_observability_report)

    p_afp = sub.add_parser(
        "auto-fix-proxy",
        help="One-shot dead localhost proxy fix + 60s background guardian install.",
    )
    p_afp.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview only — no registry mutation or guardian install.",
    )
    p_afp.add_argument(
        "--skip-guardian-install",
        action="store_true",
        help="Fix now but do not install startup background guardian.",
    )
    p_afp.add_argument(
        "--skip-cursor-fix",
        action="store_true",
        help="Skip configure-cursor-no-proxy.ps1 step.",
    )
    p_afp.add_argument(
        "--prefer-direct",
        action="store_true",
        help="Also clear an active localhost WinINET proxy (requires --confirm PREFER_DIRECT_WININET).",
    )
    p_afp.add_argument(
        "--confirm",
        dest="confirm_phrase",
        default="",
        help="PREFER_DIRECT_WININET when using --prefer-direct.",
    )
    p_afp.add_argument(
        "--guardian-interval",
        type=int,
        default=15,
        dest="guardian_interval",
        help="Background guardian check interval in seconds (default 15, hold-direct loop).",
    )
    p_afp.add_argument("--json", dest="emit_json", action="store_true")
    p_afp.set_defaults(func=cmd_auto_fix_proxy, dry_run=False)

    p_eph = sub.add_parser(
        "ensure-proxy-health",
        help=(
            "Session ensure: clear dead localhost WinINET, install startup observability, "
            "optional --prefer-direct for LinkedIn/browser reliability."
        ),
    )
    p_eph.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview only — no registry mutation or install.",
    )
    p_eph.add_argument(
        "--prefer-direct",
        action="store_true",
        help="Also clear an active localhost WinINET proxy (requires --confirm PREFER_DIRECT_WININET).",
    )
    p_eph.add_argument(
        "--confirm",
        dest="confirm_phrase",
        default="",
        help="PREFER_DIRECT_WININET when using --prefer-direct.",
    )
    p_eph.add_argument(
        "--skip-observability-install",
        action="store_true",
        help="Skip installing guardian + boot trace if missing.",
    )
    p_eph.add_argument(
        "--skip-cursor-fix",
        action="store_true",
        help="Skip configure-cursor-no-proxy.ps1 step.",
    )
    p_eph.add_argument(
        "--guardian-interval",
        type=int,
        default=15,
        dest="guardian_interval",
        help="Guardian check interval in seconds (default 15).",
    )
    p_eph.add_argument("--json", dest="emit_json", action="store_true")
    p_eph.set_defaults(func=cmd_ensure_proxy_health, dry_run=False)

    p_dns = sub.add_parser(
        "dns-health",
        help="Read-only Wi-Fi DNS heuristic for DNS_PROBE_FINISHED_BAD_CONFIG triage.",
    )
    p_dns.add_argument(
        "--interface",
        default="Wi-Fi",
        dest="interface_alias",
        help="Adapter alias to inspect (default Wi-Fi).",
    )
    p_dns.add_argument("--json", dest="emit_json", action="store_true")
    p_dns.set_defaults(func=cmd_dns_health)

    p_proxy = sub.add_parser("proxy", help="Grouped proxy commands.")
    p_proxy_sub = p_proxy.add_subparsers(dest="proxy_cmd", required=True)
    p_proxy_disable = p_proxy_sub.add_parser(
        "disable",
        help="Preview/apply safe HKCU WinINET proxy disable (default dry-run).",
    )
    p_proxy_disable.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        help="Preview only by default. Use --dry-run false with --confirm DISABLE_WININET_PROXY to apply.",
    )
    p_proxy_disable.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live apply requires exact phrase DISABLE_WININET_PROXY.",
    )
    p_proxy_disable.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_proxy_disable.add_argument("--no-clear-server", action="store_false", dest="clear_server")
    p_proxy_disable.add_argument("--no-clear-autoconfig", action="store_false", dest="clear_autoconfig")
    p_proxy_disable.add_argument("--soak-minutes", type=float, default=0.0)
    p_proxy_disable.add_argument("--soak-poll-seconds", type=float, default=5.0)
    p_proxy_disable.add_argument(
        "--stop-listener-first",
        action="store_true",
        help="Before disable apply, run stop-listener (requires --stop-listener-confirm STOP_PROXY_LISTENER).",
    )
    p_proxy_disable.add_argument(
        "--stop-listener-confirm",
        type=str,
        default="",
        dest="stop_listener_confirm_phrase",
        metavar="PHRASE",
        help="Typed phrase STOP_PROXY_LISTENER when using --stop-listener-first on live apply.",
    )
    _add_proxy_stop_reverter_arguments(p_proxy_disable, include_chained=True)
    p_proxy_disable.set_defaults(
        func=cmd_proxy_disable,
        clear_server=True,
        clear_autoconfig=True,
        stop_listener_first=False,
        stop_reverter_first=False,
        stop_parent_tree=False,
    )

    p_proxy_restore_lkg = p_proxy_sub.add_parser(
        "restore-lkg",
        help="Restore HKCU WinINET proxy fields from latest known-good snapshot (typed-confirmation gated; default dry-run).",
    )
    p_proxy_restore_lkg.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        type=_parse_bool_arg,
        help="Preview only by default. Use --dry-run false with --confirm RESTORE_WININET_PROXY_FROM_LKG to apply.",
    )
    p_proxy_restore_lkg.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Live restore requires exact phrase RESTORE_WININET_PROXY_FROM_LKG.",
    )
    p_proxy_restore_lkg.add_argument(
        "--name",
        type=str,
        default="",
        dest="snapshot_name",
        metavar="NAME",
        help="Optional snapshot label; defaults to the youngest stored snapshot.",
    )
    p_proxy_restore_lkg.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_proxy_restore_lkg.set_defaults(func=cmd_proxy_restore_lkg)

    p_proxy_cc = p_proxy_sub.add_parser(
        "config-check",
        help="Read-only proxy config audit (WinINET, WinHTTP, Git, npm, env, browser policy).",
    )
    p_proxy_cc.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_proxy_cc.set_defaults(func=cmd_proxy_config_check)

    p_proxy_rwp = p_proxy_sub.add_parser(
        "registry-writer-proof",
        help="Read-only Sysmon / Security 4657 / Procmon CSV evidence for WinINET proxy registry writes.",
    )
    p_proxy_rwp.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_proxy_rwp.add_argument("--since-seconds", type=int, default=120, help="Lookback window in seconds (default 120).")
    p_proxy_rwp.add_argument(
        "--procmon-csv",
        type=str,
        default=None,
        dest="procmon_csv",
        metavar="PATH",
        help="Optional Procmon CSV export to enrich evidence.",
    )
    p_proxy_rwp.set_defaults(func=cmd_proxy_registry_writer_proof)

    p_agent = sub.add_parser("agent", help="Bounded local agent surfaces (recommendation only; no mutation).")
    p_agent_sub = p_agent.add_subparsers(dest="agent_cmd", required=True)
    p_agent_ns = p_agent_sub.add_parser(
        "next-step",
        help="Recommend the next read-only probe or preview action based on the latest stored diagnosis.",
    )
    p_agent_ns.add_argument(
        "--goal",
        type=str,
        default="suggest_next_probe",
        choices=(
            "suggest_next_probe",
            "rank_hypotheses",
            "explain_risk",
            "recommend_preview_action",
            "summarize_audit",
            "identify_missing_evidence",
        ),
        help="Bounded planner goal.",
    )
    p_agent_ns.add_argument(
        "--run-id",
        type=str,
        default="",
        dest="run_id",
        metavar="DIAGNOSIS_ID",
        help="Optional diagnosis run id; defaults to the latest stored diagnosis.",
    )
    p_agent_ns.add_argument("--json", dest="emit_json", action="store_true", help="Emit structured JSON only.")
    p_agent_ns.set_defaults(func=cmd_agent_next_step)

    p_sn = sub.add_parser("snapshot", help="Persist full observability JSON under reports/snapshots/.")
    p_sn.set_defaults(func=cmd_snapshot)

    p_dl = sub.add_parser(
        "diagnose-live",
        help="Snapshot + deterministic v2 hypotheses + live recommendations (or offline --replay run_id).",
        description=(
            "Preferred long-form name for the live stack. Equivalent to `python -m src diagnose --live`; "
            "add `--replay RUN_ID` (or Top-level command `replay`) for offline parity checks."
        ),
    )
    p_dl.add_argument("--json", dest="emit_json", action="store_true", help="Stdout JSON payload only.")
    p_dl.add_argument(
        "--both",
        dest="emit_both",
        action="store_true",
        help="Human-readable summary first, then JSON_PAYLOAD_START … JSON_PAYLOAD_END wrapping the same payload.",
    )
    p_dl.add_argument(
        "--proofs",
        dest="live_proofs",
        action="store_true",
        help="Run read-only Proof Engine (HTTPS via localhost proxy vs bypass) and attach hypothesis_decisions.",
    )
    p_dl.add_argument(
        "--replay",
        dest="replay_run_id",
        default=None,
        metavar="RUN_ID",
        help=(
            "Offline: load logs/decision_runs.jsonl by run_id — same as `python -m src replay RUN_ID`. "
            "Use `--json` for JSON-only tooling output; `--both` for human plus JSON markers."
        ),
    )
    p_dl.set_defaults(func=cmd_diagnose_live, live_proofs=False, emit_both=False)

    p_replay_cli = sub.add_parser(
        "replay",
        help="Offline replay: parity check a saved live run from logs/decision_runs.jsonl.",
        description=(
            "Recomputes deterministic scores from archived observations — no probes. "
            "RUN_ID equals `diagnosis_id` / `run_id` in the audit row. "
            "`--json` prints the structured parity object only; `--both` emits narration then JSON_PAYLOAD delimiters. "
            "Positional RUN_ID overrides `--run-id` when both are set."
        ),
    )
    p_replay_cli.add_argument(
        "replay_positional_id",
        nargs="?",
        default=None,
        metavar="RUN_ID",
        help="UUID/key from logs/decision_runs.jsonl (same as diagnose-live `--replay`).",
    )
    p_replay_cli.add_argument(
        "--run-id",
        dest="replay_flag_id",
        default=None,
        metavar="RUN_ID",
        help="Same UUID as positional RUN_ID; ignored when positional is provided.",
    )
    p_replay_cli.add_argument("--json", dest="emit_json", action="store_true", help="JSON report on stdout only.")
    p_replay_cli.add_argument(
        "--both",
        dest="emit_both",
        action="store_true",
        help="Human execution-flow text, then extractable JSON between JSON_PAYLOAD_* lines.",
    )
    p_replay_cli.set_defaults(func=cmd_replay, emit_json=False, emit_both=False)

    p_plhp = sub.add_parser(
        "proof-localhost-https",
        help="Proof Engine: causal HTTPS probe via localhost proxy vs curl --noproxy (no config changes).",
    )
    p_plhp.add_argument(
        "--url",
        dest="proof_test_url",
        default="https://www.google.com",
        metavar="HTTPS_URL",
        help="Target URL for HTTPS contrast probes (default: %(default)s).",
    )
    p_plhp.set_defaults(func=cmd_proof_localhost_https)

    p_pv = sub.add_parser(
        "preview",
        help="Explainable read-only preview of tiered repairs from latest diagnosis (no scripts run).",
        description=(
            "Shows diagnose / repair_safe / guided / advanced tiers from `last_diagnosis_live.json` "
            "(preferred) or legacy `last_diagnosis.json`. Use `--both` when you want human text plus extractable JSON."
        ),
    )
    p_pv.add_argument("--json", dest="emit_json_preview", action="store_true", help="Structured tiers JSON only.")
    p_pv.add_argument(
        "--both",
        dest="emit_both_preview",
        action="store_true",
        help="Tier list for humans, then JSON_PAYLOAD markers with the `--json` object.",
    )
    p_pv.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="App-path scenario preview (e.g. chatgpt_app_firewall).",
    )
    p_pv.add_argument(
        "--recovery-feedback",
        type=str,
        default=None,
        dest="recovery_feedback",
        metavar="HINT",
        help="Recovery verification hint, e.g. firewall_reset_helped.",
    )
    p_pv.set_defaults(func=cmd_preview, emit_json_preview=False, emit_both_preview=False)

    p_rem = sub.add_parser(
        "remediate",
        help="Preview-gated remediation for app-path scenarios (dry-run default).",
    )
    p_rem.add_argument(
        "--scenario",
        type=str,
        required=True,
        help="Scenario id (e.g. chatgpt_app_firewall).",
    )
    p_rem.add_argument(
        "--dry-run",
        nargs="?",
        const=True,
        default=True,
        type=lambda v: str(v).lower() not in {"false", "0", "no"},
        help="Preview only (default). Use --dry-run false with --confirm for allowlisted LOW actions.",
    )
    p_rem.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help="Typed confirmation for allowlisted LOW actions when --dry-run false.",
    )
    p_rem.add_argument(
        "--recovery-feedback",
        type=str,
        default=None,
        dest="recovery_feedback",
        metavar="HINT",
    )
    p_rem.add_argument("--json", dest="emit_json", action="store_true")
    p_rem.set_defaults(func=cmd_remediate)

    p_rp = sub.add_parser(
        "repair-preview",
        help="Synonym for `preview` — tiered repairs from latest diagnosis artifact.",
    )
    p_rp.add_argument("--json", dest="emit_json_preview", action="store_true", help="Structured JSON only.")
    p_rp.add_argument("--both", dest="emit_both_preview", action="store_true", help="Human tiers + JSON delimiters.")
    p_rp.set_defaults(func=cmd_repair_preview, emit_json_preview=False, emit_both_preview=False)

    p_ra = sub.add_parser(
        "repair-apply",
        help="Interactively launch first LOW-tier script like repair-safe (live or legacy).",
    )
    p_ra.add_argument("--dry-run", action="store_true", help="List candidates without elevation.")
    p_ra.set_defaults(func=cmd_repair_apply)

    p_ns = sub.add_parser(
        "network-state",
        help="Network State Manager: named snapshots, drift diff, policy, reports, preview/restore.",
    )
    ns_sub = p_ns.add_subparsers(dest="network_state_cmd", required=True)

    p_nss = ns_sub.add_parser("snapshot", help="Save or manage known-good snapshots.")
    nss_sub = p_nss.add_subparsers(dest="network_state_snapshot_cmd", required=True)

    p_nss_sv = nss_sub.add_parser(
        "save",
        help="Capture WinINET, WinHTTP, Git, npm, user proxy env → logs/network_state_snapshots.jsonl.",
    )
    p_nss_sv.add_argument("--name", required=True, dest="snapshot_name", metavar="NAME", help="Profile label.")
    p_nss_sv.set_defaults(func=cmd_network_state_snapshot_save)

    p_nss_ls = nss_sub.add_parser("list", help="List profile names + default flag.")
    p_nss_ls.set_defaults(func=cmd_network_state_snapshot_list)

    p_nss_sh = nss_sub.add_parser("show", help="Print latest JSONL record for --name.")
    p_nss_sh.add_argument("--name", required=True, dest="snapshot_name", metavar="NAME")
    p_nss_sh.set_defaults(func=cmd_network_state_snapshot_show)

    p_nss_sd = nss_sub.add_parser("set-default", help="Write config/network_state_default.json from latest --name.")
    p_nss_sd.add_argument("--name", required=True, dest="snapshot_name", metavar="NAME")
    p_nss_sd.set_defaults(func=cmd_network_state_snapshot_set_default)

    p_nsdiff = ns_sub.add_parser("diff", help="Compare current machine vs saved snapshot or default profile.")
    g_ns = p_nsdiff.add_mutually_exclusive_group(required=True)
    g_ns.add_argument("--name", dest="snapshot_name", metavar="NAME")
    g_ns.add_argument("--default", dest="use_default", action="store_true", help="Use config/network_state_default.json.")
    p_nsdiff.add_argument("--json", dest="json_out", action="store_true")
    p_nsdiff.set_defaults(snapshot_name=None, use_default=False, func=cmd_network_state_diff)

    p_ns_rep = ns_sub.add_parser("report", help="Summarize recent events + drift vs default.")
    p_ns_rep.add_argument("--since", default="24h", help="Window like 24h, 7d, 30m.")
    p_ns_rep.add_argument("--json", dest="json_out", action="store_true")
    p_ns_rep.set_defaults(func=cmd_network_state_report)

    p_ns_rs = ns_sub.add_parser(
        "restore",
        help='Preview or restore named snapshot (live requires --confirm RESTORE_NETWORK_STATE; default is dry-run preview).',
    )
    p_ns_rs.add_argument("--name", required=True, dest="snapshot_name", metavar="NAME")
    p_ns_rs.add_argument("--dry-run", action="store_true", help="Force preview only.")
    p_ns_rs.add_argument(
        "--confirm",
        type=str,
        default="",
        dest="confirm_phrase",
        metavar="PHRASE",
        help='Typed phrase RESTORE_NETWORK_STATE enables live argv-only restores.',
    )
    p_ns_rs.set_defaults(func=cmd_network_state_restore)

    p_ns_ev = ns_sub.add_parser("evidence", help="Import optional Procmon-style CSV (no tracers installed).")
    ev_sub = p_ns_ev.add_subparsers(dest="network_state_evidence_cmd", required=True)
    p_ns_ev_imp = ev_sub.add_parser("import", help="Append normalized rows to logs/network_state_evidence.jsonl.")
    p_ns_ev_imp.add_argument("--file", required=True, dest="evidence_file", metavar="PATH")
    p_ns_ev_imp.set_defaults(func=cmd_network_state_evidence_import)

    p_edge = sub.add_parser(
        "edge-diagnose",
        help="Simulated AI-edge/embedded-compute reliability reasoning (no hardware).",
        description=(
            "Deterministic edge reasoning: observation -> event -> state transition -> ranked "
            "hypotheses -> evidence tree -> optional simulated proof -> impact -> policy -> "
            "append-only audit (logs/edge_runs.jsonl). Use --fixture PATH or --live-simulated."
        ),
    )
    edge_src = p_edge.add_mutually_exclusive_group(required=True)
    edge_src.add_argument("--fixture", type=str, default=None, help="Load edge observations JSON fixture.")
    edge_src.add_argument(
        "--live-simulated",
        dest="live_simulated",
        action="store_true",
        help="Generate deterministic simulated device telemetry (no hardware access).",
    )
    p_edge.add_argument(
        "--profile",
        type=str,
        default=None,
        help="Simulation profile for --live-simulated (e.g. thermal, npu_fallback, latency, driver, sensor, uplink).",
    )
    p_edge.add_argument(
        "--action",
        dest="requested_action",
        type=str,
        default=None,
        metavar="ACTION",
        help="Optional remediation action key to evaluate (preview-gated; destructive keys are blocked).",
    )
    p_edge.add_argument(
        "--confirm",
        dest="confirm",
        action="store_true",
        help="Treat operator confirmation as present (ALLOW still requires CONFIRMED proof + low risk).",
    )
    p_edge.add_argument("--json", dest="emit_json", action="store_true", help="Emit full machine-readable contract.")
    p_edge.set_defaults(func=cmd_edge_diagnose, live_simulated=False, confirm=False, emit_json=False)

    p_edge_replay = sub.add_parser(
        "edge-replay",
        help="Replay a stored edge run by id from logs/edge_runs.jsonl (read-only, no re-simulation).",
    )
    p_edge_replay.add_argument("run_id", metavar="RUN_ID", help="Edge run id from a prior edge-diagnose.")
    p_edge_replay.set_defaults(func=cmd_edge_replay)

    p_ir = sub.add_parser(
        "incident-review",
        help="Generate incident review from case study or platform JSONL (read-only).",
    )
    p_ir.add_argument("--incident-id", required=True, dest="incident_id", metavar="ID")
    p_ir.add_argument(
        "--format",
        dest="review_format",
        choices=("markdown", "json"),
        default="markdown",
    )
    p_ir.set_defaults(func=cmd_incident_review)

    p_pv = sub.add_parser("policy-validate", help="Validate a policy-as-code YAML profile.")
    p_pv.add_argument("policy_path", metavar="policy.yaml")
    p_pv.set_defaults(func=cmd_policy_validate)

    p_fs = sub.add_parser("fleet-simulate", help="Fixture-based fleet simulation (no live mutation).")
    p_fs.add_argument("--scenario", dest="fleet_scenario", default="proxy-drift")
    p_fs.add_argument("--endpoints", dest="fleet_endpoints", type=int, default=25)
    p_fs.add_argument("--incidents", dest="fleet_incidents", type=int, default=None)
    p_fs.set_defaults(func=cmd_fleet_simulate)

    p_demo = sub.add_parser("demo-scenario", help="Run deterministic evidence/policy demo fixture.")
    p_demo.add_argument("demo_scenario", choices=list(SCENARIOS.keys()))
    p_demo.add_argument(
        "--format", dest="demo_format", choices=("markdown", "json", "both"), default="markdown"
    )
    p_demo.set_defaults(func=cmd_demo_scenario)

    p_fr = sub.add_parser("fleet-report", help="Summarize last fleet simulation output.")
    p_fr.add_argument(
        "--format",
        dest="fleet_report_format",
        choices=("markdown", "json"),
        default="markdown",
    )
    p_fr.set_defaults(func=cmd_fleet_report)

    p_plat = sub.add_parser(
        "platform",
        help="Multi-domain decision platform (fixture-based, research/preview only).",
    )
    plat_sub = p_plat.add_subparsers(dest="platform_cmd", required=True)

    p_pe = plat_sub.add_parser("events", help="List normalized events from domain fixtures.")
    p_pe.add_argument(
        "--domain",
        dest="platform_domain",
        choices=("windows", "security", "cloud", "infrastructure", "market"),
        default=None,
    )
    p_pe.add_argument("--fixture", dest="platform_fixture", default=None)
    p_pe.add_argument("--format", dest="platform_format", choices=("json",), default="json")
    p_pe.set_defaults(func=cmd_platform_events)

    p_pve = plat_sub.add_parser("evidence", help="Build evidence tree for an event.")
    p_pve.add_argument("--event-id", required=True, dest="event_id")
    p_pve.add_argument("--format", dest="platform_format", choices=("json",), default="json")
    p_pve.add_argument("--audit-path", dest="audit_path", default=None)
    p_pve.set_defaults(func=cmd_platform_evidence)

    p_pd = plat_sub.add_parser("decide", help="Rank decisions for an event (policy-gated).")
    p_pd.add_argument("--event-id", required=True, dest="event_id")
    p_pd.add_argument("--format", dest="platform_format", choices=("json",), default="json")
    p_pd.add_argument("--audit-path", dest="audit_path", default=None)
    p_pd.set_defaults(func=cmd_platform_decide)

    p_po = plat_sub.add_parser("outcome", help="Record a decision outcome (learning metrics).")
    p_po.add_argument("--decision-id", required=True, dest="decision_id")
    p_po.add_argument("--failure", action="store_true", help="Record unsuccessful outcome.")
    p_po.add_argument("--observed-result", dest="observed_result", default="fixture_simulated")
    p_po.add_argument("--cost-score", type=float, default=0.1)
    p_po.add_argument("--time-to-resolution", type=float, default=120.0)
    p_po.add_argument("--lessons", default="Fixture outcome recorded.")
    p_po.add_argument("--format", dest="platform_format", choices=("json",), default="json")
    p_po.set_defaults(func=cmd_platform_outcome)

    p_pr = plat_sub.add_parser("replay", help="Replay all domain fixtures deterministically.")
    p_pr.add_argument("--domain", dest="platform_domain", default=None)
    p_pr.add_argument("--fixture", dest="platform_fixture", default=None)
    p_pr.add_argument("--audit-path", dest="audit_path", default=None)
    p_pr.add_argument("--format", dest="platform_format", choices=("json",), default="json")
    p_pr.set_defaults(func=cmd_platform_replay)

    p_pm = plat_sub.add_parser("metrics", help="Outcome and platform learning metrics.")
    p_pm.add_argument("--audit-path", dest="audit_path", default=None)
    p_pm.add_argument("--format", dest="platform_format", choices=("json",), default="json")
    p_pm.set_defaults(func=cmd_platform_metrics)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse argv and delegate to registered subcommand handler.

    Raises:
        SystemExit propagates indirectly through argparse misuse (handled externally).

    Returns:
        Integral POSIX-style exit status from the dispatched command handler.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "func", None)
    if handler is None:
        parser.print_help()
        return 1
    try:
        return int(handler(args))
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON in diagnosis snapshot: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

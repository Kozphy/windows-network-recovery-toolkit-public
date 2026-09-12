"""CLI entrypoint for ``python -m windows_network_toolkit`` and ``python -m toolkit``.

Module responsibility:
    Parse subcommands and delegate to library modules. All JSON output uses UTF-8 and
    ``ensure_ascii=False`` for operator readability.

System placement:
    Top-level operator interface for evidence collection, analytics, governance reports,
    and gated remediation preview/apply. Business logic lives in sibling modules — this
    file wires argparse only.

Key invariants:
    * ``proxy-disable`` / ``ipv6-prefer-ipv4`` / ``dns-edge-fix`` default to ``--dry-run true``.
    * Read-only: ``proxy-status``, ``proxy-health``, ``ipv6-path-status``, ``dns-edge-status``.
    * Fixture resolution searches ``tests/fixtures/`` and ``windows_network_toolkit/examples/``.

Side effects:
    Varies by subcommand — see individual ``cmd_*`` handlers. Mutating paths:
    ``proxy-disable`` / ``ipv6-prefer-ipv4`` / ``dns-edge-fix`` (when dry-run false + typed confirm),
    optional ``--out`` writes.

Failure modes:
    Exit code 1 for validation/confirmation failures; 2 for unsupported platform (non-Windows
    remediation). Fixture not found prints to stderr and returns 1.

Audit Notes:
    * Prefer dry-run before live apply; confirm token required for apply.
    * Analytics and evidence commands are read-only — safe for portfolio demos on fixtures.

Engineering Notes:
    Subcommand handlers stay thin to preserve testability of underlying modules and to avoid
    duplicating policy logic already enforced in ``proxy_remediation`` and ``safety``.

See also: ``docs/ONBOARDING.md`` and ``docs/code-documentation-standards.md``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from windows_network_toolkit.audit.replay import replay_to_dict
from windows_network_toolkit.audit.report_generator import generate_erp_report, generate_report


def _emit_json(payload: dict | list) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def _load_fixture_data(path_str: str) -> dict:
    path = _resolve_fixture(path_str)
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_fixture(path_str: str) -> Path:
    path = Path(path_str)
    if path.is_file():
        return path
    repo = Path(__file__).resolve().parents[1]
    for candidate in (
        repo / "windows_network_toolkit" / "examples" / path_str,
        repo / "tests" / "fixtures" / "enert" / path_str,
        repo / "tests" / "fixtures" / "enert" / f"{path_str}.json",
        repo / "tests" / "fixtures" / "classification" / path_str,
        repo / "tests" / "fixtures" / "classification" / f"{path_str}.json",
        repo / "tests" / "fixtures" / "case_studies" / path_str,
        repo / "tests" / "fixtures" / "case_studies" / f"{path_str}.json",
        repo / "examples" / "lan" / path_str,
        repo / "examples" / "lan" / f"{path_str}.json",
        repo / "examples" / "lan" / f"{path_str}.jsonl",
        repo / "examples" / "router" / path_str,
        repo / "tests" / "fixtures" / "lan" / path_str,
        repo / "tests" / "fixtures" / "lan" / f"{path_str}.json",
        repo / "tests" / "fixtures" / "router" / path_str,
        repo / "tests" / "fixtures" / "risk_register" / path_str,
        repo / "tests" / "fixtures" / "risk_register" / f"{path_str}.json",
        repo / "tests" / "fixtures" / "cloud_governance" / path_str,
        repo / "tests" / "fixtures" / "cloud_governance" / f"{path_str}.json",
        repo / "tests" / "fixtures" / "finops" / path_str,
        repo / "tests" / "fixtures" / "finops" / f"{path_str}.json",
    ):
        if candidate.is_file():
            return candidate
    return path


def cmd_replay(args: argparse.Namespace) -> int:
    """Run the ``replay`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``format``, ``out``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    path = _resolve_fixture(args.fixture)
    if not path.is_file():
        print(f"Fixture not found: {args.fixture}", file=sys.stderr)
        return 1
    payload = replay_to_dict(path, dry_run=True)
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(
            generate_report(
                timeline=payload["timeline"],
                decision=payload["decision"],
                policy=payload["policy"],
                remediation=payload["remediation"],
                audit_rows=[payload.get("audit") or {}],
                fmt="markdown",
            )
        )
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Run the ``report`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``format``, ``url``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    if args.fixture:
        path = _resolve_fixture(args.fixture)
        if not path.is_file():
            print(f"Fixture not found: {args.fixture}", file=sys.stderr)
            return 1
        payload = replay_to_dict(path, dry_run=True)
        text = generate_report(
            timeline=payload["timeline"],
            decision=payload["decision"],
            policy=payload["policy"],
            remediation=payload["remediation"],
            audit_rows=[payload.get("audit") or {}],
            fmt=args.format,  # type: ignore[arg-type]
        )
    elif args.url:
        from windows_network_toolkit.diagnostics.proxy import run_full_incident_report

        package = run_full_incident_report(args.url)
        text = generate_erp_report(package, fmt=args.format)  # type: ignore[arg-type]
    else:
        print("Provide fixture path or --url for live diagnostic report.", file=sys.stderr)
        return 1
    print(text)
    return 0


def cmd_replay_certify(args: argparse.Namespace) -> int:
    """Run the ``replay-certify`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.replay.certifier import certify_case

    path = _resolve_fixture(args.fixture)
    cert = certify_case(jsonl_path=path)
    print(
        json.dumps(
            {
                "certified": cert.certified,
                "certification_hash": cert.certification_hash,
                "tier": cert.tier,
                "policy_outcome": cert.policy_outcome,
                "errors": cert.errors,
            },
            indent=2,
        )
    )
    return 0 if cert.certified else 1


def cmd_bad_gateway_diagnose(args: argparse.Namespace) -> int:
    """Run read-only bad-gateway (502/504) diagnostic for a target HTTPS URL.

    Args:
        args: Namespace with ``url``, optional ``json_only`` and ``summary_only``.

    Returns:
        0 on success; prints classification JSON or human summary.

    Side effects:
        Read-only probes only (DNS, TCP, curl via system vs direct path).
        May append platform audit row via runner (see bad_gateway.runner).

    Notes:
        Used by auto-fix-chatgpt.ps1 step 2; does not mutate host settings.
    """
    from windows_network_toolkit.diagnostics.bad_gateway import run_bad_gateway_diagnose

    report = run_bad_gateway_diagnose(args.url, dry_run=True)
    if args.json_only:
        print(json.dumps(report, indent=2))
    else:
        print(f"=== {report['headline']} ===")
        print(f"Classification: {report['classification']} (confidence {report['confidence']:.2f})")
        print(f"Recommended: {report['recommended_action']}")
        print(f"Policy: {report['policy_gate'].get('outcome')}")
        for note in report.get("safety_notes", []):
            print(f"  • {note}")
        if not args.summary_only:
            print(json.dumps(report, indent=2))
    return 0


def cmd_localhost_diagnose(args: argparse.Namespace) -> int:
    """Diagnose localhost web-app failures (ERR_CONNECTION_REFUSED) — read-only."""

    from windows_network_toolkit.diagnostics.localhost import (
        render_localhost_diagnose,
        run_localhost_diagnose,
    )

    inject = None
    fixture = getattr(args, "fixture", "") or ""
    if fixture:
        inject = _load_fixture_data(fixture)

    report = run_localhost_diagnose(
        url=getattr(args, "url", None) or None,
        host=getattr(args, "host", None) or None,
        port=getattr(args, "port", None),
        path=getattr(args, "path", None) or None,
        timeout=float(getattr(args, "timeout", 2.0) or 2.0),
        include_process=bool(getattr(args, "include_process", False)),
        include_http=bool(getattr(args, "include_http", False)),
        include_proxy_comparison=bool(getattr(args, "include_proxy_comparison", False)),
        include_nearby_listeners=bool(getattr(args, "include_nearby_listeners", False)),
        remediation_preview=bool(getattr(args, "remediation_preview", False)),
        evidence_out=getattr(args, "evidence_out", None) or None,
        allow_non_loopback=bool(getattr(args, "allow_non_loopback", False)),
        inject=inject,
        prior_listener_evidence=bool((inject or {}).get("prior_listener_evidence")),
        verbose=bool(getattr(args, "verbose", False)),
    )
    as_json = bool(getattr(args, "json", False)) or bool(getattr(args, "emit_json", False))
    sys.stdout.write(
        render_localhost_diagnose(
            report,
            as_json=as_json,
            verbose=bool(getattr(args, "verbose", False)),
        )
    )
    if report.get("validation_error"):
        return 2
    return 0


def cmd_localhost_watch(args: argparse.Namespace) -> int:
    """Watch a localhost target for listener/TCP/HTTP transitions — read-only."""

    from windows_network_toolkit.diagnostics.localhost import run_localhost_watch

    try:
        summary = run_localhost_watch(
            url=getattr(args, "url", None) or None,
            host=getattr(args, "host", None) or None,
            port=getattr(args, "port", None),
            path=getattr(args, "path", None) or None,
            interval=float(getattr(args, "interval", 2.0) or 2.0),
            duration=float(getattr(args, "duration", 60.0) or 60.0),
            timeout=float(getattr(args, "timeout", 2.0) or 2.0),
            include_http=bool(getattr(args, "include_http", False)),
            jsonl_out=getattr(args, "jsonl_out", None) or None,
        )
    except ValueError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def cmd_proxy_status(args: argparse.Namespace) -> int:
    """Emit read-only WinINET/WinHTTP proxy status JSON.

    Args:
        args: Namespace with optional ``fixture`` for offline state injection.

    Returns:
        0 on success.

    Side effects:
        Read-only registry/netsh when no fixture; prints JSON to stdout.
    """
    from windows_network_toolkit.diagnostics.proxy import run_proxy_status

    inject = None
    if args.fixture:
        data = _load_fixture_data(args.fixture)
        inject = data
    payload = run_proxy_status(inject=inject)
    _emit_json(payload)
    return 0


def cmd_proxy_owner(args: argparse.Namespace) -> int:
    """Emit localhost proxy listener process attribution JSON.

    Args:
        args: Namespace with optional ``fixture`` for inject envelope.

    Returns:
        0 on success.

    Side effects:
        Read-only port/process resolution when no fixture.

    Notes:
        Listener process is correlation only — not registry writer proof.
    """
    from windows_network_toolkit.proxy_owner import detect_proxy_owner

    inject = None
    if args.fixture:
        inject = _load_fixture_data(args.fixture).get("proxy_owner") or _load_fixture_data(
            args.fixture
        )
    payload = detect_proxy_owner(inject=inject)
    _emit_json(payload)
    return 0


def cmd_diagnose(args: argparse.Namespace) -> int:
    """Emit structured diagnosis JSON for a URL or fixture.

    With ``--proof``, runs the full proof envelope (signals, attempts, conclusion).
    Without ``--proof``, emits read-only proxy status summary from fixture or live probes.
    With ``--decision-context``, attaches stakeholder/timing/coordination without changing proof.
    """
    inject = None
    fixture_data: dict | None = None
    if args.fixture:
        fixture_data = _load_fixture_data(args.fixture)
        inject = fixture_data.get("proof") or fixture_data

    if not getattr(args, "proof", False):
        from windows_network_toolkit.diagnostics.proxy import run_proxy_status

        payload = run_proxy_status(inject=inject or fixture_data)
        if fixture_data and fixture_data.get("classification"):
            payload["classification"] = fixture_data["classification"]
        payload["proof_mode"] = "summary"
        payload["recommended_next_step"] = "Re-run with --proof for full proof envelope"
        _emit_json(payload)
        return 0

    from src.platform_core.governance.proof_tier import resolve_proof_tier
    from src.platform_core.policy.outcome_normalizer import normalize_policy_outcome
    from windows_network_toolkit.proof import enrich_diagnose_payload, run_diagnose_proof

    payload = run_diagnose_proof(args.url or None, inject=inject)
    out = payload.to_dict()
    if fixture_data:
        tier = resolve_proof_tier(fixture_data)
        out["proof_tier"] = tier.proof_tier.value
        out["proof_tier_label"] = tier.proof_tier_label
        pol = fixture_data.get("policy_decision") or {}
        gate = normalize_policy_outcome(str(pol.get("outcome", "PREVIEW_ONLY")))
        out["policy_gate"] = gate.value
        out["recommended_next_step"] = (
            f"Policy gate: {gate.value}; preview remediation before apply"
        )
    if getattr(args, "principles", False):
        out = enrich_diagnose_payload(out, include_principles=True)
    out["proof_mode"] = "full"

    if getattr(args, "decision_context", False):
        from platform_core.models import utc_now_iso
        from src.platform_core.decision_context import (
            build_decision_envelope,
            format_decision_text,
            save_decision_envelope,
        )

        classification = ""
        if isinstance(out.get("classification"), dict):
            classification = str(out["classification"].get("primary_classification") or "")
        elif fixture_data and isinstance(fixture_data.get("classification"), dict):
            classification = str(fixture_data["classification"].get("primary_classification") or "")
        pol = (fixture_data or {}).get("policy_decision") or {}
        case_id = str((fixture_data or {}).get("case_id") or out.get("incident_id") or "")
        if not case_id:
            from platform_core.models import utc_now_iso

            case_id = f"diag-{utc_now_iso().replace(':', '').replace('+', 'p')}"
        envelope = build_decision_envelope(
            case_id=case_id,
            decision_id=str(out.get("decision_id") or case_id),
            classification=classification,
            policy_decision=str(pol.get("outcome") or out.get("policy_gate") or "PREVIEW_ONLY"),
            policy_allowed=bool(pol.get("allowed", False)),
            policy_requires_approval=bool(pol.get("requires_confirmation", True)),
            proof_result=out,
            timezone_name=getattr(args, "timezone", None) or None,
            write_audit=True,
        )
        save_decision_envelope(envelope)
        out["decision_context"] = envelope.to_dict()
        out["policy_decision"] = envelope.policy_decision
        out["coordination_status"] = envelope.coordination_status.value
        if getattr(args, "format", "json") == "text":
            print(format_decision_text(envelope))
            return 0

    _emit_json(out)
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    """Emit package version JSON (read-only; no admin privileges)."""
    from windows_network_toolkit import SERVICE_NAME, __version__

    _emit_json(
        {
            "package": "windows-network-recovery-toolkit",
            "version": __version__,
            "service": SERVICE_NAME,
            "read_only": True,
            "requires_admin": False,
        }
    )
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Start the read-only local NiceGUI monitoring dashboard.

    Args:
        args: Namespace with ``dashboard_host``, ``dashboard_port``, ``watch_interval``,
            ``max_visible_events``, ``storage_path``, ``allow_non_loopback_bind``.

    Returns:
        ``0`` on clean exit; ``2`` on bind/config/missing-dependency errors.

    Side effects:
        Binds HTTP on host:port; starts proxy watcher; appends JSONL evidence events.
        Does not remediate proxy/registry/process state.

    Audit Notes:
        Rejects ``0.0.0.0`` / ``::`` unless ``--allow-non-loopback-bind``. Review
        ``.audit/dashboard-events.jsonl`` after a session.
    """

    from windows_network_toolkit.dashboard import DashboardConfig, run_dashboard

    host = str(getattr(args, "dashboard_host", None) or "127.0.0.1")
    if host in {"0.0.0.0", "::", "[::]"} and not bool(
        getattr(args, "allow_non_loopback_bind", False)
    ):
        print(
            "Refusing to bind on all interfaces. Use --host 127.0.0.1 "
            "or pass --allow-non-loopback-bind only if you accept the exposure risk.",
            file=sys.stderr,
        )
        return 2
    storage = getattr(args, "storage_path", "") or ""
    try:
        run_dashboard(
            DashboardConfig(
                host=host,
                port=int(getattr(args, "dashboard_port", 8765) or 8765),
                watch_interval=float(getattr(args, "watch_interval", 1.0) or 1.0),
                max_visible_events=int(getattr(args, "max_visible_events", 200) or 200),
                storage_path=Path(storage) if storage else None,
            )
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return int(exc.code) if isinstance(exc.code, int) else 2
    return 0


def cmd_procmon_import(args: argparse.Namespace) -> int:
    """Import Procmon CSV registry writes into normalized evidence events.

    Args:
        args: Namespace with ``procmon_csv``, optional ``storage_path``, ``max_visible_events``.

    Returns:
        ``0`` with JSON summary on success; ``2`` when CSV is missing/invalid.

    Side effects:
        Appends imported events to ``EvidenceEventStore`` (JSONL). Does not write HKCU.
        Does not launch Procmon.

    Audit Notes:
        Imported RegSetValue rows are process-level write observations — not intent proof.
    """

    from windows_network_toolkit.collectors.procmon_import import (
        ProcmonImportError,
        import_procmon_csv,
        import_procmon_csv_summary,
    )
    from windows_network_toolkit.storage.event_store import EvidenceEventStore

    csv_path = getattr(args, "procmon_csv", None)
    try:
        summary = import_procmon_csv_summary(str(csv_path))
    except ProcmonImportError as exc:
        print(json.dumps({"error": exc.to_dict()}, indent=2))
        return 2

    store = EvidenceEventStore(
        max_visible=int(getattr(args, "max_visible_events", 200) or 200),
        storage_path=Path(args.storage_path) if getattr(args, "storage_path", "") else None,
        persist=True,
    )
    for ev in import_procmon_csv(str(csv_path)):
        store.append(ev)

    _emit_json(summary)
    return 0


def cmd_principles_explain(_args: argparse.Namespace) -> int:
    """Run the ``principles-explain`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include no command-specific fields.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.principles.validator import explain_principles

    _emit_json(explain_principles())
    return 0


def cmd_principles_validate(args: argparse.Namespace) -> int:
    """Run the ``principles-validate`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.principles.validator import validate_fixture_path

    path = args.fixture
    if not path:
        repo = Path(__file__).resolve().parents[1]
        path = str(repo / "case_studies" / "cs1_wininet_proxy_drift" / "fixture.json")
    result = validate_fixture_path(path)
    _emit_json(result.to_dict())
    return 0 if result.compliant else 1


def cmd_proxy_guardian(args: argparse.Namespace) -> int:
    """Auto-clear dead localhost WinINET proxy when no listener is bound."""
    from windows_network_toolkit.proxy_guardian import run_proxy_guardian_once

    dry_run = args.dry_run.lower() != "false"
    payload = run_proxy_guardian_once(dry_run=dry_run)
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    if payload.get("action_taken") == "blocked":
        return 1
    return 0


def cmd_auto_fix_chatgpt(args: argparse.Namespace) -> int:
    """Run ChatGPT auto-fix pipeline (proxy, diagnose, LOW-risk remediations).

    Args:
        args: Namespace with ``dry_run``, ``confirm``, ``url``, ``skip_proxy_auto_fix``,
            ``skip_guardian_install``.

    Returns:
        0 when outcome healthy; 1 when degraded; 2 on unsupported platform.

    Side effects:
        Delegates to ``run_auto_fix_chatgpt`` — see ``src.network_recovery.auto_fix``.

    Audit Notes:
        Emits JSON steps payload; audit rows in ``logs/network_recovery_events.jsonl``.
    """
    from src.network_recovery.auto_fix import run_auto_fix_chatgpt

    dry_run = args.dry_run.lower() != "false"
    payload = run_auto_fix_chatgpt(
        dry_run=dry_run,
        confirm=args.confirm or "",
        skip_proxy_auto_fix=bool(getattr(args, "skip_proxy_auto_fix", False)),
        skip_guardian_install=bool(getattr(args, "skip_guardian_install", False)),
        chatgpt_url=args.url or "https://chatgpt.com",
    )
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    if payload.get("outcome") == "degraded":
        return 1
    return 0


def cmd_proxy_disable(args: argparse.Namespace) -> int:
    """Run gated WinINET proxy disable (preview by default).

    Args:
        args: Namespace with ``dry_run`` (default true) and ``confirm`` token.

    Returns:
        0 on preview success or allowed apply; 1 when apply blocked; 2 on non-Windows.

    Side effects:
        When ``dry_run`` is false and confirmation matches, mutates HKCU WinINET registry
        via ``run_proxy_disable`` and appends ``proxy-disable.jsonl`` audit rows.

    Audit Notes:
        Live apply requires typed confirmation phrase — never bypass via CLI flags alone.
    """
    from windows_network_toolkit.proxy_remediation import run_proxy_disable

    dry_run = args.dry_run.lower() != "false"
    payload = run_proxy_disable(dry_run=dry_run, confirm=args.confirm or "")
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    if not dry_run and not payload.get("action_allowed"):
        return 1
    return 0


def cmd_ipv6_path(args: argparse.Namespace) -> int:
    """One-shot IPv6 path investigate (proxy/DNS/Wi-Fi + multi-host probes).

    Args:
        args: Optional ``probe_url``, ``timeout``, and ``prefer_ipv4`` remediation flags.

    Returns:
        0 on success/preview; 1 when prefer-IPv4 apply blocked; 2 unsupported platform.

    Side effects:
        Read-only by default. With ``--prefer-ipv4 --dry-run false`` may write HKLM.
    """
    from windows_network_toolkit.ipv6_path import investigate_ipv6_path, run_prefer_ipv4

    prefer = bool(getattr(args, "prefer_ipv4", False))
    if prefer:
        dry_run = args.dry_run.lower() != "false"
        rem = run_prefer_ipv4(
            dry_run=dry_run,
            confirm=args.confirm or "",
            diagnose_first=True,
        )
        inv = investigate_ipv6_path(
            probe_url=args.probe_url or None,
            timeout=float(args.timeout),
        )
        payload = {
            "timestamp_utc": rem.get("timestamp_utc"),
            "command": "ipv6-path",
            "investigate": inv,
            "prefer_ipv4": rem,
            "operator_next_step": rem.get("elevated_apply_command")
            if rem.get("status") == "needs_elevation"
            else (
                inv.get("operator_next_step")
                if dry_run
                else {
                    "kind": rem.get("status"),
                    "command": None,
                    "reason": rem.get("message"),
                }
            ),
            "limitations": rem.get("limitations") or inv.get("limitations"),
        }
        from src.platform_core.governance.evidence_to_action import attach_governance_envelope

        # investigate/rem already enveloped; emit combined without double-wrapping governance twice
        if "governance" not in payload:
            payload = attach_governance_envelope(payload)
        else:
            payload.setdefault("governance", rem.get("governance") or inv.get("governance"))
        _emit_json(payload)
        if rem.get("unsupported_platform") or inv.get("unsupported_platform"):
            return 2
        if not dry_run and not rem.get("action_allowed"):
            return 1
        return 0

    payload = investigate_ipv6_path(
        probe_url=args.probe_url or None,
        timeout=float(args.timeout),
    )
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    return 0


def cmd_ipv6_path_status(args: argparse.Namespace) -> int:
    """Read-only IPv4 vs IPv6 HTTPS path diagnosis (blackhole pattern).

    Args:
        args: Optional ``probe_url`` and ``timeout``.

    Returns:
        0 on success; 2 when platform unsupported without injected probes.

    Side effects:
        Outbound curl HTTPS probes only — no registry writes.
    """
    from windows_network_toolkit.ipv6_path import diagnose_ipv6_path

    payload = diagnose_ipv6_path(
        probe_url=args.probe_url or None,
        timeout=float(args.timeout),
        use_fallbacks=not bool(getattr(args, "no_fallback", False)),
    )
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    return 0


def cmd_ipv6_prefer_ipv4(args: argparse.Namespace) -> int:
    """Preview/apply prefer-IPv4 (Tcpip6 DisabledComponents bit 0x20).

    Args:
        args: ``dry_run`` (default true) and ``confirm`` token.

    Returns:
        0 on preview/noop/applied; 1 when apply blocked; 2 on non-Windows.

    Side effects:
        Live apply writes HKLM DisabledComponents and may flush DNS; requires elevation
        and exact ``PREFER_IPV4_OVER_IPV6`` confirmation. Does not disable adapters.
    """
    from windows_network_toolkit.ipv6_path import run_prefer_ipv4

    dry_run = args.dry_run.lower() != "false"
    payload = run_prefer_ipv4(
        dry_run=dry_run,
        confirm=args.confirm or "",
        diagnose_first=not dry_run or args.diagnose,
    )
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    if not dry_run and not payload.get("action_allowed"):
        return 1
    return 0


def cmd_ipv6_restore_preference(args: argparse.Namespace) -> int:
    """Preview/clear prefer-IPv4 bit to restore IPv6 preference.

    Args:
        args: ``dry_run`` (default true) and ``confirm`` token.

    Returns:
        0 on preview/noop/applied; 1 when apply blocked; 2 on non-Windows.

    Side effects:
        Live apply clears HKLM DisabledComponents bit 0x20; requires elevation and
        ``RESTORE_IPV6_PREFERENCE``. Reboot recommended after apply.
    """
    from windows_network_toolkit.ipv6_path import run_restore_ipv6_preference

    dry_run = args.dry_run.lower() != "false"
    payload = run_restore_ipv6_preference(
        dry_run=dry_run,
        confirm=args.confirm or "",
    )
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    if not dry_run and not payload.get("action_allowed"):
        return 1
    return 0


def cmd_dns_edge_status(args: argparse.Namespace) -> int:
    """Read-only DNS + Edge policy diagnosis for ERR_NAME_NOT_RESOLVED.

    Side effects:
        DNS lookups and registry/adapter reads only.
    """
    from windows_network_toolkit.dns_edge import diagnose_dns_edge

    payload = diagnose_dns_edge(interface_alias=args.interface or "Wi-Fi")
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    return 0


def cmd_dns_edge_fix(args: argparse.Namespace) -> int:
    """Preview/apply public-DNS-first + Edge OS-resolver fix.

    Side effects:
        Live apply may change Wi-Fi DNS, HKCU Edge policy, flush DNS, and optionally
        stop msedge.exe when ``--restart-edge`` is set.
    """
    from windows_network_toolkit.dns_edge import run_dns_edge_fix

    dry_run = args.dry_run.lower() != "false"
    payload = run_dns_edge_fix(
        dry_run=dry_run,
        confirm=args.confirm or "",
        interface_alias=args.interface or "Wi-Fi",
        restart_edge=bool(args.restart_edge),
        diagnose_first=True,
    )
    _emit_json(payload)
    if payload.get("unsupported_platform"):
        return 2
    if not dry_run and not payload.get("action_allowed"):
        return 1
    return 0


def cmd_proxy_watch(args: argparse.Namespace) -> int:
    """Poll WinINET proxy for drift; append changes to proxy-watch JSONL.

    Args:
        args: ``duration``, ``interval``, ``coalesce_ms``, ``fixture``, format flags.

    Returns:
        0 on success; 2 when platform unsupported without fixture.

    Side effects:
        Appends ``.audit/proxy-watch.jsonl``; runs health probes on localhost transitions.

    Audit Notes:
        Read-only on registry — no auto-disable. Reverter flags require human review.
    """
    from windows_network_toolkit.watch import format_proxy_change_human, run_proxy_watch

    inject_sequence = None
    health_inject = None
    if args.fixture:
        data = _load_fixture_data(args.fixture)
        inject_sequence = data.get("watch_sequence")
        health_inject = data.get("health_inject")
    payload = run_proxy_watch(
        duration=int(args.duration),
        interval=float(args.interval),
        coalesce_ms=int(args.coalesce_ms),
        inject_sequence=inject_sequence,
        health_inject=health_inject,
        run_direct_probe=not args.no_direct_probe,
        run_proxy_probe=not args.no_proxy_probe,
        timeout_seconds=float(args.timeout),
    )
    if payload.get("unsupported_platform"):
        _emit_json(payload)
        return 2
    if args.format == "human":
        changes = [e for e in payload.get("events", []) if e.get("event") == "proxy_change"]
        if not changes:
            print("No proxy changes detected during watch window.")
        for ch in changes:
            print(format_proxy_change_human(ch))
            print()
        if args.json_also:
            _emit_json(payload)
    else:
        _emit_json(payload)
    return 0


def cmd_proxy_replay(args: argparse.Namespace) -> int:
    """Replay proxy-watch JSONL through state machine and control tests.

    Args:
        args: ``input`` JSONL path, ``coalesce_ms``, ``format`` (json|human).

    Returns:
        0 on success.

    Side effects:
        Read-only — no host mutation.
    """
    from windows_network_toolkit.proxy_replay import replay_proxy_file

    payload = replay_proxy_file(
        args.input,
        coalesce_ms=int(args.coalesce_ms),
    )
    if args.format == "human":
        summary = payload.get("summary") or {}
        print(
            f"Replay: {summary.get('input_event_count', 0)} input rows -> {summary.get('coalesced_event_count', 0)} classified events"
        )
        for ev in payload.get("events") or []:
            print(json.dumps(ev, indent=2))
            print()
        for ctrl in payload.get("controls") or []:
            print(f"{ctrl.get('control_id')}: {ctrl.get('status')}")
        if args.json_also:
            _emit_json(payload)
    else:
        _emit_json(payload)
    return 0


def cmd_proxy_health(args: argparse.Namespace) -> int:
    """Run localhost proxy health probes and emit human or JSON audit payload.

    Args:
        args: Supports ``--fixture``, ``--json``, probe toggles, and optional ``--host``/``--port``.

    Returns:
        0 always on successful probe run (health failure is data, not CLI error).

    Side effects:
        Network probes when not using fixture inject; read-only on registry.
    """
    from windows_network_toolkit.proxy_health import (
        build_proxy_health_audit_payload,
        check_localhost_proxy_health,
        classify_incident_from_health,
        format_proxy_health_human,
        run_proxy_health_for_state,
    )
    from windows_network_toolkit.proxy_owner import detect_proxy_owner
    from windows_network_toolkit.proxy_state import collect_proxy_state_model

    fixture_data: dict = {}
    inject_state = None
    health_inject = None
    owner_inject = None
    if args.fixture:
        fixture_data = _load_fixture_data(args.fixture)
        inject_state = fixture_data.get("proxy_state") or fixture_data
        health_inject = fixture_data.get("health_inject")
        owner_inject = fixture_data.get("proxy_owner")

    state = collect_proxy_state_model(inject=inject_state).to_dict()
    urls = list(args.url) if args.url else None
    health_kwargs: dict = {
        "test_urls": urls,
        "timeout_seconds": float(args.timeout),
        "run_direct_probe": not args.no_direct_probe,
        "run_proxy_probe": not args.no_proxy_probe,
        "inject": health_inject,
    }

    if args.host and args.port:
        owner_payload = owner_inject or detect_proxy_owner(inject_state=inject_state)
        health = check_localhost_proxy_health(
            args.host,
            int(args.port),
            listener_info=owner_payload,
            **{k: v for k, v in health_kwargs.items() if v is not None},
        )
        classification = classify_incident_from_health(health, wininet_enabled=True)
        payload = build_proxy_health_audit_payload(
            wininet=state,
            health=health,
            classification=classification,
        )
    else:
        owner_payload = detect_proxy_owner(inject=owner_inject, inject_state=inject_state)
        payload = run_proxy_health_for_state(state, owner_payload, **health_kwargs)

    if args.json:
        _emit_json(payload)
    else:
        print(format_proxy_health_human(payload))
        if args.json_also:
            print()
            _emit_json(payload)
    return 0


def cmd_proxy_report(args: argparse.Namespace) -> int:
    """Run the ``proxy-report`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``url``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.report import build_proxy_report

    inject = None
    if args.fixture:
        inject = _load_fixture_data(args.fixture).get("report") or _load_fixture_data(args.fixture)
    payload = build_proxy_report(
        url=args.url or None,
        inject=inject,
        include_principles=bool(getattr(args, "include_principles", False)),
    )
    _emit_json(payload)
    return 0


def cmd_proxy_attribution(args: argparse.Namespace) -> int:
    """Emit read-only proxy listener attribution JSON.

    Args:
        args: No fixture — live collection only.

    Returns:
        0 on success.

    Side effects:
        Read-only process/port correlation.
    """
    from windows_network_toolkit.diagnostics.proxy import run_proxy_attribution

    payload = run_proxy_attribution()
    print(json.dumps(payload, indent=2))
    return 0


def cmd_proxy_writer_attribution(args: argparse.Namespace) -> int:
    """Emit registry writer attribution with optional Sysmon fixture inject.

    Args:
        args: Optional ``fixture`` with ``writer_attribution`` and ``sysmon_events``.

    Returns:
        0 on success.

    Side effects:
        May read EventLog/Sysmon when live; fixture mode is read-only.

    Notes:
        Writer proof requires telemetry — absence is not proof of benign intent.
    """
    from src.platform_core.attribution.writer_engine import run_proxy_writer_attribution

    inject = None
    inject_sysmon = None
    if args.fixture:
        path = _resolve_fixture(args.fixture)
        data = json.loads(path.read_text(encoding="utf-8"))
        inject = data.get("writer_attribution")
        inject_sysmon = data.get("sysmon_events")
    payload = run_proxy_writer_attribution(inject=inject, inject_sysmon=inject_sysmon)
    print(json.dumps(payload.to_dict(), indent=2))
    return 0


def cmd_tls_proof(args: argparse.Namespace) -> int:
    """Contrast TLS certificate paths direct vs proxied (read-only).

    Args:
        args: ``url`` and optional ``fixture`` with ``tls_proof`` / ``root_store``.

    Returns:
        0 on success.

    Side effects:
        HTTPS handshakes when live — no registry mutation.

    Notes:
        Path mismatch supports triage — not confirmed MITM or malware.
    """
    from src.platform_core.tls import run_tls_proof

    inject = None
    inject_roots = None
    if args.fixture:
        path = _resolve_fixture(args.fixture)
        data = json.loads(path.read_text(encoding="utf-8"))
        inject = data.get("tls_proof")
        inject_roots = data.get("root_store")
    payload = run_tls_proof(args.url, inject=inject, inject_roots=inject_roots)
    print(json.dumps(payload.to_dict(), indent=2))
    return 0


def cmd_website_risk(args: argparse.Namespace) -> int:
    """Run the ``website-risk`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``url``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.website_risk import run_website_risk

    inject = None
    if args.fixture:
        path = _resolve_fixture(args.fixture)
        data = json.loads(path.read_text(encoding="utf-8"))
        inject = data.get("website_risk")
    payload = run_website_risk(args.url, inject=inject)
    print(json.dumps(payload.to_dict(), indent=2))
    return 0


def cmd_evidence_report(args: argparse.Namespace) -> int:
    """Generate evidence report (latest proxy package, analytics, or URL assessment).

    Args:
        args: ``--latest`` for proxy-path package; ``--analytics`` for pipeline report;
            ``--url`` for full evidence assessment; optional ``fixture`` and ``--out``.

    Returns:
        0 on success; 1 when required ``--url`` missing for non-latest mode.

    Side effects:
        Read-only evidence collection; optional write to ``--out`` path.

    Notes:
        Reports include ``limitations[]`` — management information, not audit opinions.
    """
    if getattr(args, "executive", False):
        from src.platform_core.analytics.executive_evidence_report import (
            export_executive_evidence_report,
            format_executive_evidence_markdown,
        )

        report = export_executive_evidence_report(
            risk_register_path=Path(args.risk_register)
            if getattr(args, "risk_register", None)
            else None,
            cloud_fixture_path=Path(args.cloud_fixture)
            if getattr(args, "cloud_fixture", None)
            else None,
            finops_fixture_path=Path(args.finops_fixture)
            if getattr(args, "finops_fixture", None)
            else None,
            audit_dir=Path(args.audit_dir) if getattr(args, "audit_dir", None) else None,
            out_path=Path(args.out) if args.out else None,
            fmt=args.format if args.format in ("json", "markdown") else "markdown",
        )
        if args.out:
            if args.format == "json":
                _emit_json(report)
            else:
                print(format_executive_evidence_markdown(report))
        elif args.format == "json":
            _emit_json(report)
        else:
            print(format_executive_evidence_markdown(report))
        return 0

    if getattr(args, "latest", False):
        from windows_network_toolkit.latest_evidence_report import (
            build_latest_evidence_package,
            render_latest_evidence_markdown,
        )

        inject_state = inject_owner = inject_health = inject_timeline = inject_reverter = None
        if args.fixture:
            data = _load_fixture_data(args.fixture)
            inject_state = data.get("proxy_state") or data
            inject_owner = data.get("proxy_owner")
            inject_health = data.get("health_inject")
            inject_timeline = data.get("timeline")
            inject_reverter = data.get("reverter_diagnosis")
        package = build_latest_evidence_package(
            inject_state=inject_state,
            inject_owner=inject_owner,
            inject_health=inject_health,
            inject_timeline=inject_timeline,
            inject_reverter=inject_reverter,
            health_kwargs={
                "run_direct_probe": not getattr(args, "no_direct_probe", False),
                "run_proxy_probe": not getattr(args, "no_proxy_probe", False),
            },
        )
        if args.format == "json":
            _emit_json(package)
        else:
            text = render_latest_evidence_markdown(package)
            print(text)
        if args.out:
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            content = (
                json.dumps(package, indent=2)
                if args.format == "json"
                else render_latest_evidence_markdown(package)
            )
            out.write_text(content, encoding="utf-8")
        return 0

    if getattr(args, "analytics", False):
        from windows_network_toolkit.analytics_pipeline import (
            render_analytics_evidence_report,
            run_endpoint_analytics_pipeline,
        )

        fixture = None
        if args.fixture:
            fixture = _load_fixture_data(args.fixture)
        payload = run_endpoint_analytics_pipeline(fixture=fixture)
        print(render_analytics_evidence_report(payload))
        if args.out:
            Path(args.out).write_text(render_analytics_evidence_report(payload), encoding="utf-8")
        return 0

    from src.platform_core.evidence_report import generate_evidence_report
    from windows_network_toolkit.diagnostics.evidence import run_evidence_assessment

    if not args.url:
        print("Provide --url or use --latest for proxy-path evidence report.", file=sys.stderr)
        return 1

    inject_writer = inject_proof = inject_tls = inject_website = inject_sysmon = None
    if args.fixture:
        path = _resolve_fixture(args.fixture)
        data = json.loads(path.read_text(encoding="utf-8"))
        inject_writer = data.get("writer_attribution")
        inject_proof = data.get("proof_results")
        inject_tls = data.get("tls_proof")
        inject_website = data.get("website_risk")
        inject_sysmon = data.get("sysmon_events")

    package = run_evidence_assessment(
        args.url,
        inject_writer=inject_writer,
        inject_proof=inject_proof,
        inject_tls=inject_tls,
        inject_website=inject_website,
        inject_sysmon=inject_sysmon,
    )
    text = generate_evidence_report(package, fmt=args.format)  # type: ignore[arg-type]
    print(text)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    return 0


def cmd_proxy_proof(args: argparse.Namespace) -> int:
    """Emit direct vs proxied path proof JSON for a URL (read-only).

    Args:
        args: Target ``url``.

    Returns:
        0 on success.

    Side effects:
        Network probes only — no registry mutation.
    """
    from windows_network_toolkit.diagnostics.proxy import run_proxy_proof

    payload = run_proxy_proof(args.url)
    print(json.dumps(payload, indent=2))
    return 0


def cmd_proxy_timeline(args: argparse.Namespace) -> int:
    """Run the ``proxy-timeline`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``audit``, ``audit_only``, ``url``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.proxy import run_proxy_timeline
    from windows_network_toolkit.timeline import build_proxy_timeline

    if args.audit_only:
        payload = build_proxy_timeline()
    else:
        payload = run_proxy_timeline(args.url or None, use_audit=bool(args.audit))
    _emit_json(payload)
    return 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify hash chain integrity of an audit JSONL file.

    Args:
        args: ``audit_file`` path to JSONL records; optional tip check flags.

    Returns:
        0 when chain verifies (and tip when requested); 1 when file missing or invalid.

    Side effects:
        Read-only file read.

    Audit Notes:
        Chain integrity proves append-only consistency — not truth of observations.
        Tip match proves consistency with a previously written tip file — not WORM.
    """
    from src.platform_core.audit.tip_anchor import verify_audit_with_tip
    from src.platform_core.governance.chain_of_custody import verify_chain

    path = Path(args.audit_file)
    if not path.is_file():
        print(f"Audit file not found: {path}", file=sys.stderr)
        return 1

    check_tip = bool(getattr(args, "check_tip", False) or getattr(args, "require_tip", False))
    if check_tip:
        tip = Path(args.tip_path) if getattr(args, "tip_path", "") else None
        result = verify_audit_with_tip(
            path,
            tip_path=tip,
            require_tip=bool(getattr(args, "require_tip", False)),
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("verified") else 1

    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    ok, msg = verify_chain(records)
    print(json.dumps({"verified": ok, "message": msg, "records": len(records)}, indent=2))
    return 0 if ok else 1


def cmd_risk_assess(args: argparse.Namespace) -> int:
    """Run the ``risk-assess`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.risk import assess_risk, load_fixture

    fixture = load_fixture(_resolve_fixture(args.fixture))
    _emit_json(assess_risk(fixture))
    return 0


def cmd_control_test(args: argparse.Namespace) -> int:
    """Run the ``control-test`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.risk import load_fixture, run_control_tests
    from src.platform_core.risk.control_test_mature import run_mature_control_tests

    fixture = load_fixture(_resolve_fixture(args.fixture))
    tests = run_control_tests(fixture)
    mature = run_mature_control_tests(fixture)
    _emit_json(
        {
            "schema_version": "technology_risk_decision.v1",
            "command": "control-test",
            "case_id": fixture.get("case_id"),
            "control_tests": [t.model_dump() for t in tests],
            "mature_control_tests": [t.model_dump() for t in mature],
        }
    )
    return 0


def cmd_governance_report(args: argparse.Namespace) -> int:
    """Run the ``governance-report`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``audit_dir``, ``audit_dir_kpi``, ``fixture``, ``format``, ``risk_register``, ``timezone``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.governance.audit_report import build_audit_governance_report
    from src.platform_core.risk import build_governance_report, load_fixture

    if getattr(args, "audit_dir", None):
        audit_dir = Path(args.audit_dir)
        result = build_audit_governance_report(
            audit_dir,
            risk_register_path=Path(args.risk_register)
            if getattr(args, "risk_register", None)
            else None,
            format=args.format,
        )
        if args.format in ("markdown", "html"):
            print(result)
        else:
            _emit_json(result)
        return 0

    if not getattr(args, "fixture", None):
        print("governance-report requires --fixture or --audit-dir", file=sys.stderr)
        return 2

    fixture = load_fixture(_resolve_fixture(args.fixture))
    if getattr(args, "include_decision_context", False):
        fixture = dict(fixture)
        fixture["include_decision_context"] = True
        if getattr(args, "timezone", None):
            fixture["timezone"] = args.timezone
        if getattr(args, "audit_dir_kpi", None):
            fixture["audit_dir"] = args.audit_dir_kpi
    result = build_governance_report(
        fixture, format=args.format if args.format != "html" else "markdown"
    )
    if args.format == "markdown":
        print(result)
    elif args.format == "html":
        from src.platform_core.governance.audit_report import _markdown_to_html

        print(_markdown_to_html(str(result)))
    else:
        _emit_json(result)
    return 0


def cmd_stakeholder_resolve(args: argparse.Namespace) -> int:
    """Resolve stakeholder roles for a stored case (roles/config only)."""
    from src.platform_core.decision_context import load_decision_envelope
    from src.platform_core.stakeholder import resolve_stakeholders

    case_id = str(args.case_id)
    existing = load_decision_envelope(case_id)
    classification = getattr(args, "classification", "") or ""
    policy_outcome = getattr(args, "policy_outcome", "") or "PREVIEW_ONLY"
    if existing and existing.stakeholder and not classification:
        classification = existing.stakeholder.classification
    if existing and not getattr(args, "policy_outcome", ""):
        policy_outcome = existing.policy_decision
    config = None
    if getattr(args, "config", None):
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    ctx = resolve_stakeholders(
        case_id=case_id,
        classification=classification,
        policy_outcome=policy_outcome,
        policy_requires_approval=bool(getattr(args, "requires_approval", True)),
        config=config,
    )
    _emit_json(ctx.to_dict())
    return 0


def cmd_timing_evaluate(args: argparse.Namespace) -> int:
    """Evaluate timing/SLA/window for a case (does not authorize execution)."""
    from platform_core.models import utc_now_iso
    from src.platform_core.decision_context import load_decision_envelope
    from src.platform_core.timing import evaluate_timing

    case_id = str(args.case_id)
    existing = load_decision_envelope(case_id)
    detected = getattr(args, "detected_at", None) or (
        existing.timing.detected_at_utc if existing and existing.timing else utc_now_iso()
    )
    classification = getattr(args, "classification", "") or (
        existing.stakeholder.classification if existing and existing.stakeholder else ""
    )
    tm = evaluate_timing(
        case_id=case_id,
        detected_at_utc=str(detected),
        timezone_name=getattr(args, "timezone", None) or None,
        classification=classification,
        policy_outcome=(existing.policy_decision if existing else "PREVIEW_ONLY"),
        maintenance_window_required=bool(getattr(args, "maintenance_window_required", False)),
        change_freeze_active=bool(getattr(args, "change_freeze", False)),
    )
    _emit_json(tm.to_dict())
    return 0


def cmd_decision_explain(args: argparse.Namespace) -> int:
    """Explain a stored DecisionEnvelope without inventing stronger causation."""
    from src.platform_core.decision_context import (
        explain_decision_envelope,
        format_decision_text,
        load_decision_envelope,
    )

    env = load_decision_envelope(str(args.case_id))
    if env is None:
        print(f"No decision context for case-id={args.case_id}", file=sys.stderr)
        return 2
    if getattr(args, "format", "json") == "text":
        print(format_decision_text(env))
        return 0
    _emit_json(explain_decision_envelope(env))
    return 0


def cmd_risk_kpi_summary(args: argparse.Namespace) -> int:
    """Run the ``risk-kpi-summary`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``audit_dir``, ``format``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.analytics import build_risk_kpi_summary, format_risk_kpi_markdown

    audit_dir = Path(args.audit_dir)
    payload = build_risk_kpi_summary(audit_dir)
    if args.format == "markdown":
        print(format_risk_kpi_markdown(payload))
    else:
        _emit_json(payload)
    return 0


def cmd_risk_matrix(args: argparse.Namespace) -> int:
    """Export risk matrix heat-map data (read-only)."""
    from src.platform_core.risk.risk_matrix import export_risk_matrix

    register = _resolve_fixture(args.register) if getattr(args, "register", None) else None
    out = Path(args.out) if getattr(args, "out", None) else None
    payload = export_risk_matrix(
        register_path=register,
        out_path=out,
        fmt=args.format,
    )
    if args.format == "json" and not out:
        _emit_json(payload)
    elif args.format == "json" and out:
        _emit_json({k: v for k, v in payload.items() if k != "matrix_rows"})
    else:
        _emit_json(payload)
    return 0


def cmd_cloud_recommendations(args: argparse.Namespace) -> int:
    """Summarize mock cloud governance recommendations (read-only)."""
    from src.platform_core.cloud_governance import (
        format_cloud_summary_markdown,
        summarize_cloud_recommendations,
    )

    fixture = _resolve_fixture(args.fixture) if getattr(args, "fixture", None) else None
    summary = summarize_cloud_recommendations(fixture_path=fixture)
    if args.format == "markdown":
        print(format_cloud_summary_markdown(summary))
    else:
        _emit_json(summary)
    return 0


def cmd_finops_export(args: argparse.Namespace) -> int:
    """Export mock FinOps cost facts (read-only)."""
    from src.platform_core.finops import export_finops

    fixture = _resolve_fixture(args.fixture) if getattr(args, "fixture", None) else None
    out_dir = Path(args.out_dir) if getattr(args, "out_dir", None) else None
    payload = export_finops(fixture_path=fixture, out_dir=out_dir, fmt=args.format)
    _emit_json(payload)
    return 0


def cmd_powerbi_export(args: argparse.Namespace) -> int:
    """Run the ``powerbi-export`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``audit_dir``, ``cloud_fixture``, ``finops_fixture``, ``out_dir``, ``risk_register``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.analytics.powerbi_star_export import export_powerbi_star_schema

    audit_dir = Path(args.audit_dir)
    out_dir = Path(args.out_dir)
    payload = export_powerbi_star_schema(
        audit_dir,
        out_dir,
        include_seed=not getattr(args, "no_seed", False),
        risk_register_path=Path(args.risk_register)
        if getattr(args, "risk_register", None)
        else None,
        cloud_fixture_path=Path(args.cloud_fixture)
        if getattr(args, "cloud_fixture", None)
        else None,
        finops_fixture_path=Path(args.finops_fixture)
        if getattr(args, "finops_fixture", None)
        else None,
    )
    _emit_json(payload)
    return 0


def cmd_analytics_export_powerbi(args: argparse.Namespace) -> int:
    """Run the ``analytics-export-powerbi`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``audit_dir``, ``out_dir``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.analytics.powerbi_export import (
        export_powerbi_from_audit,
        write_portfolio_sample,
    )

    out_dir = Path(args.out_dir)
    if getattr(args, "portfolio_sample", False):
        counts = write_portfolio_sample(out_dir)
        _emit_json(
            {
                "schema_version": "powerbi_export.v1",
                "command": "analytics-export-powerbi",
                "mode": "portfolio_sample",
                "out_dir": str(out_dir.resolve()),
                "record_counts": counts,
            }
        )
        return 0

    audit_dir = Path(args.audit_dir)
    payload = export_powerbi_from_audit(
        audit_dir,
        out_dir,
        include_portfolio_seed=bool(getattr(args, "include_seed", False)),
    )
    _emit_json(payload)
    return 0


def cmd_analytics_summary(args: argparse.Namespace) -> int:
    """Run the ``analytics-summary`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``audit_dir``, ``fixture``, ``format``, ``input``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    if getattr(args, "legacy_platform", False):
        from src.platform_core.analytics import build_analytics_summary, format_analytics_markdown

        audit_dir = Path(args.audit_dir)
        payload = build_analytics_summary(audit_dir)
        if args.format == "markdown":
            print(format_analytics_markdown(payload))
        else:
            _emit_json(payload)
        return 0

    from windows_network_toolkit.analytics_pipeline import (
        format_endpoint_analytics_summary_human,
        render_analytics_evidence_report,
        run_endpoint_analytics_pipeline,
    )

    fixture = None
    if args.fixture:
        fixture = _load_fixture_data(args.fixture)
    input_path = Path(args.input) if getattr(args, "input", "") else None
    payload = run_endpoint_analytics_pipeline(
        input_path=input_path,
        fixture=fixture,
        bucket=getattr(args, "bucket", "day") or "day",
        limit_processes=int(getattr(args, "limit_processes", 10) or 10),
    )
    if getattr(args, "json", False) or args.format == "json":
        _emit_json(payload)
    elif args.format == "markdown":
        print(render_analytics_evidence_report(payload))
    else:
        print(format_endpoint_analytics_summary_human(payload))
    return 0


def cmd_analytics_export(args: argparse.Namespace) -> int:
    """Run the ``analytics-export`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``bucket``, ``fixture``, ``format``, ``input``, ``limit_processes``, ``out``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.analytics_pipeline import (
        export_endpoint_analytics,
        run_endpoint_analytics_pipeline,
    )

    fixture = None
    if args.fixture:
        fixture = _load_fixture_data(args.fixture)
    input_path = Path(args.input) if args.input else None
    payload = run_endpoint_analytics_pipeline(
        input_path=input_path,
        fixture=fixture,
        bucket=args.bucket,
        limit_processes=int(args.limit_processes),
    )
    out_dir = Path(args.out)
    paths = export_endpoint_analytics(
        payload,
        out_dir,
        export_csv=args.format in ("csv", "both"),
    )
    _emit_json(
        {
            "schema_version": "endpoint_evidence_analytics.v1",
            "out_dir": str(out_dir.resolve()),
            "files": paths,
        }
    )
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the ``demo`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include no command-specific fields.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    repo = Path(__file__).resolve().parents[1]
    fixture = repo / "windows_network_toolkit" / "examples" / "proxy_drift_incident.jsonl"
    payload = replay_to_dict(fixture, dry_run=True)
    print("=== Endpoint Reliability Golden Demo ===")
    print(f"Fixture: {fixture.name}")
    print(f"Incident type: {payload['decision'].get('incident_type')}")
    print(f"Policy: {payload['policy'].get('outcome')}")
    print()
    print(
        generate_report(
            timeline=payload["timeline"],
            decision=payload["decision"],
            policy=payload["policy"],
            remediation=payload["remediation"],
            audit_rows=[payload.get("audit") or {}],
            fmt="markdown",
        )
    )
    print()
    print("Dashboard: http://127.0.0.1:8000/dashboard/  (run: make demo-api)")
    return 0


def cmd_reviewer_demo(args: argparse.Namespace) -> int:
    """Run the ``reviewer-demo`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``json``, ``mode``, ``out``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.reviewer_demo import run_reviewer_demo

    out_dir = Path(args.out) if args.out else None
    result = run_reviewer_demo(mode=args.mode, out_dir=out_dir)
    if args.json:
        _emit_json(result)
    return 0


def cmd_fleet_simulate(args: argparse.Namespace) -> int:
    """Run the ``fleet-simulate`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``endpoints``, ``out``, ``scenario``, ``seed``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.fleet_simulate import run_fleet_simulate

    summary = run_fleet_simulate(
        scenario=args.scenario,
        endpoints=int(args.endpoints),
        seed=int(args.seed),
        out_dir=Path(args.out),
    )
    _emit_json(summary)
    return 0


def cmd_fleet_benchmark(args: argparse.Namespace) -> int:
    """Run the ``fleet-benchmark`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``endpoints``, ``format``, ``out``, ``scenario``, ``seed``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.fleet_benchmark import (
        render_fleet_benchmark_markdown,
        run_fleet_benchmark,
    )

    out_dir = Path(args.out).parent if args.out else Path("reports/benchmarks/run")
    if args.out and args.format != "markdown":
        out_dir = Path(args.out)
    summary = run_fleet_benchmark(
        scenario=args.scenario,
        endpoints=int(args.endpoints),
        seed=int(args.seed),
        out_dir=out_dir,
    )
    if args.format == "markdown":
        md = render_fleet_benchmark_markdown(summary)
        if args.out:
            Path(args.out).write_text(md, encoding="utf-8")
        else:
            print(md)
    else:
        _emit_json(summary)
    return 0


def cmd_browser_evidence(args: argparse.Namespace) -> int:
    """Run the ``browser-evidence`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``format``, ``headed``, ``out``, ``url``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from pathlib import Path

    from windows_network_toolkit.browser_evidence import load_browser_package_from_fixture
    from windows_network_toolkit.collectors.playwright_collector import collect_browser_evidence

    out_dir = Path(args.out)
    if args.fixture:
        pkg = load_browser_package_from_fixture(Path(args.fixture))
    elif args.url:
        pkg = collect_browser_evidence(args.url, out_dir, headless=not args.headed)
        manifest = out_dir / "browser_package.json"
        manifest.write_text(pkg.model_dump_json(indent=2), encoding="utf-8")
    else:
        print("Provide --url or --fixture", file=sys.stderr)
        return 2
    payload = {"browser_evidence": pkg.model_dump(), "raw_snapshot": pkg.to_raw_snapshot()}
    if args.format == "json":
        _emit_json(payload)
    else:
        print(pkg.model_dump_json(indent=2))
    return 0


def cmd_browser_diff(args: argparse.Namespace) -> int:
    """Run the ``browser-diff`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``browser``, ``fixture``, ``format``, ``import_normal_har``, ``import_private_har``, ``proof``, ``url``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from pathlib import Path

    from windows_network_toolkit.diagnostics.browser_profile import run_browser_diff

    fixture = Path(args.fixture) if getattr(args, "fixture", "") else None
    normal = Path(args.import_normal_har) if getattr(args, "import_normal_har", "") else None
    private = Path(args.import_private_har) if getattr(args, "import_private_har", "") else None
    if fixture is None and not args.url:
        print("Provide URL or --fixture", file=sys.stderr)
        return 2
    result = run_browser_diff(
        args.url or "https://example.invalid/",
        browser=args.browser,
        proof=bool(args.proof),
        normal_har=normal,
        private_har=private,
        fixture=fixture if fixture and fixture.is_file() else None,
    )
    payload = result.to_dict()
    if args.format == "text":
        print(result.text_report)
    else:
        _emit_json(payload)
    return 0


def cmd_browser_profile(args: argparse.Namespace) -> int:
    """Run the ``browser-profile`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``browser``, ``browser_profile_cmd``, ``confirm``, ``domain``, ``preview_id``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.browser_profile import (
        run_browser_profile_inspect,
        run_browser_site_state,
        run_repair_apply,
        run_repair_preview,
    )

    sub = args.browser_profile_cmd
    if sub == "inspect":
        _emit_json(run_browser_profile_inspect(browser=args.browser))
        return 0
    if sub == "site-state":
        _emit_json(run_browser_site_state(args.domain, browser=args.browser))
        return 0
    if sub == "repair-preview":
        _emit_json(run_repair_preview(args.domain, browser=args.browser))
        return 0
    if sub == "repair-apply":
        _emit_json(run_repair_apply(args.preview_id, confirm=args.confirm or ""))
        return 0
    print("Unknown browser-profile subcommand", file=sys.stderr)
    return 2


def cmd_classifier_benchmark(args: argparse.Namespace) -> int:
    """Run the ``classifier-benchmark`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``cases``, ``format``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.evaluation.classifier_benchmark import (
        load_benchmark_cases,
        render_classifier_benchmark_markdown,
        run_classifier_benchmark,
    )

    cases = load_benchmark_cases(Path(args.cases))
    summary = run_classifier_benchmark(cases)
    if args.format == "markdown":
        print(render_classifier_benchmark_markdown(summary))
    else:
        _emit_json(summary.model_dump())
    return 0


def cmd_replay_benchmark(args: argparse.Namespace) -> int:
    """Run the ``replay-benchmark`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``cases``, ``format``, ``replay_count``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from src.platform_core.evaluation.replay_benchmark import (
        load_replay_cases,
        render_replay_benchmark_markdown,
        run_replay_benchmark,
    )

    cases = load_replay_cases(Path(args.cases))
    summary = run_replay_benchmark(cases, replay_count=int(args.replay_count))
    if args.format == "markdown":
        print(render_replay_benchmark_markdown(summary))
    else:
        _emit_json(summary.model_dump())
    return 0


def cmd_lan_inventory(args: argparse.Namespace) -> int:
    """Run the ``lan-inventory`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``subnet``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.lan_privacy.collectors import collect_inventory

    inject = None
    if args.fixture:
        data = _load_fixture_data(args.fixture)
        inject = data if "devices" in data else data
    payload = collect_inventory(subnet_override=args.subnet or "", inject=inject)
    _emit_json(payload)
    return 0 if payload.get("ok", True) else 1


def cmd_lan_watch(args: argparse.Namespace) -> int:
    """Run the ``lan-watch`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``audit_path``, ``duration``, ``fixture``, ``interval``, ``mdns``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.lan_privacy.watch import run_lan_watch

    inject_sequence = None
    if args.fixture:
        data = _load_fixture_data(args.fixture)
        inject_sequence = data.get("watch_sequence") or data.get("events")
    payload = run_lan_watch(
        duration=int(args.duration),
        interval=float(args.interval),
        audit_path=args.audit_path,
        inject_sequence=inject_sequence,
        include_mdns=args.mdns,
    )
    if payload.get("unsupported_platform"):
        _emit_json(payload)
        return 2
    _emit_json(payload)
    return 0


def cmd_lan_mdns_summary(args: argparse.Namespace) -> int:
    """Run the ``lan-mdns-summary`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``duration``, ``fixture``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.lan_privacy.collectors import collect_mdns_summary

    inject = _load_fixture_data(args.fixture) if args.fixture else None
    payload = collect_mdns_summary(duration_seconds=float(args.duration), inject=inject)
    _emit_json(payload)
    return 0


def cmd_lan_ssdp_summary(args: argparse.Namespace) -> int:
    """Run the ``lan-ssdp-summary`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``duration``, ``fixture``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.lan_privacy.collectors import collect_ssdp_summary

    inject = _load_fixture_data(args.fixture) if args.fixture else None
    payload = collect_ssdp_summary(duration_seconds=float(args.duration), inject=inject)
    _emit_json(payload)
    return 0


def cmd_lan_privacy_report(args: argparse.Namespace) -> int:
    """Run the ``lan-privacy-report`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``format``, ``out_dir``, ``watch_log``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.lan_privacy.runner import (
        load_bundle,
        run_lan_privacy_report_pipeline,
    )

    if args.fixture:
        bundle = load_bundle(_resolve_fixture(args.fixture))
    elif args.watch_log:
        bundle = {"host_log": args.watch_log}
    else:
        bundle = {"host_log": ".audit/lan-watch.jsonl"}
    result = run_lan_privacy_report_pipeline(bundle, fmt=args.format, out_dir=args.out_dir or "")
    if args.format == "markdown":
        print(result.get("markdown", ""))
    elif args.format == "both":
        if result.get("markdown"):
            print(result["markdown"])
        if not args.out_dir:
            _emit_json(result["report"])
    else:
        _emit_json(result["report"])
    return 0


def cmd_lan_risk_score(args: argparse.Namespace) -> int:
    """Run the ``lan-risk-score`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.lan_privacy.runner import (
        load_bundle,
        run_lan_risk_score_pipeline,
    )

    if not args.fixture:
        print("lan-risk-score requires --fixture", file=sys.stderr)
        return 1
    bundle = load_bundle(_resolve_fixture(args.fixture))
    _emit_json(run_lan_risk_score_pipeline(bundle))
    return 0


def cmd_lan_control_test(args: argparse.Namespace) -> int:
    """Run the ``lan-control-test`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.lan_privacy.classifier import classify_lan_behavior
    from windows_network_toolkit.diagnostics.lan_privacy.privacy_risk_score import (
        compute_privacy_risk_score,
    )
    from windows_network_toolkit.diagnostics.lan_privacy.runner import (
        _resolve_observations,
        load_bundle,
    )
    from windows_network_toolkit.lan_control_tests import run_lan_control_tests

    if not args.fixture:
        print("lan-control-test requires --fixture", file=sys.stderr)
        return 1
    bundle = load_bundle(_resolve_fixture(args.fixture))
    observations, inventory, router_events = _resolve_observations(bundle)
    devices = inventory.get("devices") or []
    classification = classify_lan_behavior(observations=observations, devices=devices)
    score = compute_privacy_risk_score(
        observations=observations,
        devices=devices,
        router_events=router_events,
        classification=classification.primary_classification,
    )
    results = run_lan_control_tests(
        inventory=inventory,
        observations=observations,
        router_events=router_events,
        score_result={
            **score.to_dict(),
            "primary_classification": classification.primary_classification,
        },
    )
    _emit_json({"controls": [r.to_dict() for r in results]})
    return 0


def cmd_router_import(args: argparse.Namespace) -> int:
    """Run the ``router-import`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``input``, ``out``, ``type``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.router_evidence.runner import run_router_import

    inject = None
    if args.fixture:
        inject = _load_fixture_data(args.fixture).get("events")
    payload = run_router_import(
        import_type=args.type,
        input_path=str(_resolve_fixture(args.input)),
        out_path=args.out,
        inject=inject,
    )
    _emit_json(payload)
    return 0 if payload.get("ok") else 1


def cmd_router_correlate(args: argparse.Namespace) -> int:
    """Run the ``router-correlate`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``host_log``, ``router_log``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.router_evidence.runner import run_router_correlation

    payload = run_router_correlation(host_log=args.host_log, router_log=args.router_log)
    _emit_json(payload)
    return 0


def cmd_risk_executive_report(args: argparse.Namespace) -> int:
    """Run the ``risk-executive-report`` CLI command.

    Args:
        args: Parsed argparse namespace; fields used include ``fixture``, ``format``, ``out_dir``.

    Returns:
        Process exit code. ``0`` indicates success; non-zero values indicate missing inputs, validation failures, unsupported platforms, or blocked actions.

    Side effects:
        Prints JSON or text to stdout/stderr; may read fixtures and write requested output files."""
    from windows_network_toolkit.diagnostics.lan_privacy.executive_report import (
        render_executive_markdown,
    )
    from windows_network_toolkit.diagnostics.lan_privacy.runner import (
        load_bundle,
        run_executive_report_pipeline,
    )

    if not args.fixture:
        print("risk-executive-report requires --fixture", file=sys.stderr)
        return 1
    bundle = load_bundle(_resolve_fixture(args.fixture))
    result = run_executive_report_pipeline(bundle, fmt=args.format, out_dir=args.out_dir or "")
    if args.format == "markdown" and not args.out_dir:
        print(render_executive_markdown(result["report"]))
    elif not args.out_dir:
        _emit_json(result["report"])
    return 0


def cmd_agent_once(args: argparse.Namespace) -> int:
    """Run one read-only agent evidence cycle and append to local JSONL spool."""
    from windows_network_toolkit.agent.read_only import collect_once

    fixture = Path(args.fixture) if args.fixture else None
    if fixture and not fixture.is_file():
        print(f"Fixture not found: {fixture}", file=sys.stderr)
        return 1
    spool = Path(args.spool) if args.spool else None
    result = collect_once(
        spool_path=spool,
        os_family=args.os_family or None,
        fixture_path=fixture,
    )
    _emit_json(result)
    return 0


def cmd_agent_run(args: argparse.Namespace) -> int:
    """Run read-only agent collection loop until interrupted."""
    from windows_network_toolkit.agent.read_only import run_agent_loop

    fixture = Path(args.fixture) if args.fixture else None
    if fixture and not fixture.is_file():
        print(f"Fixture not found: {fixture}", file=sys.stderr)
        return 1
    spool = Path(args.spool) if args.spool else None
    return run_agent_loop(
        interval_seconds=float(args.interval),
        spool_path=spool,
        os_family=args.os_family or None,
        fixture_path=fixture,
        max_cycles=int(args.max_cycles) if args.max_cycles else None,
    )


def cmd_agent_health(args: argparse.Namespace) -> int:
    """Report read-only agent health and optional backend /health probe."""
    from windows_network_toolkit.agent.read_only import get_health_status

    spool = Path(args.spool) if args.spool else None
    payload = get_health_status(spool_path=spool, api_base=args.api or None)
    _emit_json(payload)
    return 0


def cmd_agent_spool_status(args: argparse.Namespace) -> int:
    """Inspect local agent JSONL spool depth (read-only)."""
    from windows_network_toolkit.agent.read_only import get_spool_status

    spool = Path(args.spool) if args.spool else None
    _emit_json(get_spool_status(spool_path=spool))
    return 0


def cmd_ai_eval(args: argparse.Namespace) -> int:
    """Run fixture-based AI eval suite and emit markdown or JSON report.

    Loads pre-recorded model outputs from a JSON cases file and evaluates them with
    deterministic checks (facts, format, citations, safety phrases, etc.). No live LLM
    or retrieval API calls are made.

    Args:
        args: Namespace with ``cases`` (fixture path) and ``format`` (``markdown`` or ``json``).

    Returns:
        0 on success.

    Side effects:
        Read-only: reads fixture file; prints report to stdout.

    Example:
        ``toolkit ai-eval --cases examples/ai_evals/support_bot_cases.json --format markdown``

    Notes:
        Policy ALLOW and pass status are structured triage signals — not deployment
        authorization or formal model safety certification.
    """
    from src.platform_core.ai_evals import load_eval_cases, render_eval_markdown, run_eval_suite

    cases = load_eval_cases(Path(args.cases))
    report = run_eval_suite(cases)
    if args.format == "markdown":
        print(render_eval_markdown(report))
    else:
        _emit_json(report.model_dump(mode="json"))
    return 0


def main(argv: list[str] | None = None, *, prog: str = "toolkit") -> int:
    """Parse CLI arguments and dispatch to the selected subcommand handler.

    Args:
        argv: Argument vector; defaults to ``sys.argv[1:]``.
        prog: Program name shown in help text.

    Returns:
        Integer exit code from the invoked ``cmd_*`` handler.

    Side effects:
        Depends on subcommand — see handler docstrings. No side effects at parse time.

    Example:
        ``python -m windows_network_toolkit proxy-health --fixture tests/fixtures/proxy_health_dead.json --json``
    """
    parser = argparse.ArgumentParser(
        prog=prog, description="Endpoint Reliability Decision Platform CLI"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ver = sub.add_parser("version", help="Print installed package version (read-only)")
    ver.set_defaults(func=cmd_version)

    dash = sub.add_parser(
        "dashboard",
        help="Start read-only local monitoring dashboard (NiceGUI on 127.0.0.1:8765)",
    )
    dash.add_argument(
        "--host", dest="dashboard_host", default="127.0.0.1", help="Bind host (default 127.0.0.1)"
    )
    dash.add_argument(
        "--port", dest="dashboard_port", type=int, default=8765, help="Bind port (default 8765)"
    )
    dash.add_argument(
        "--interval",
        dest="watch_interval",
        type=float,
        default=1.0,
        help="Proxy watcher interval seconds (default 1.0)",
    )
    dash.add_argument(
        "--max-visible-events",
        dest="max_visible_events",
        type=int,
        default=200,
        help="UI timeline ring-buffer size (default 200)",
    )
    dash.add_argument(
        "--storage-path",
        dest="storage_path",
        default="",
        help="Optional JSONL path for evidence events (default .audit/dashboard-events.jsonl)",
    )
    dash.add_argument(
        "--allow-non-loopback-bind",
        action="store_true",
        help="Allow binding to non-loopback hosts (not recommended)",
    )
    dash.set_defaults(func=cmd_dashboard)

    pmi = sub.add_parser(
        "procmon-import",
        help="Import Procmon CSV RegSetValue rows for WinINET proxy keys (read-only)",
    )
    pmi.add_argument("procmon_csv", help="Path to Procmon CSV export")
    pmi.add_argument(
        "--storage-path",
        dest="storage_path",
        default="",
        help="Optional JSONL path for imported evidence events",
    )
    pmi.add_argument(
        "--max-visible-events",
        dest="max_visible_events",
        type=int,
        default=200,
        help="In-memory ring size when persisting imports",
    )
    pmi.set_defaults(func=cmd_procmon_import)

    replay = sub.add_parser("replay", help="Replay a JSONL incident fixture")
    replay.add_argument("fixture", help="Path to JSONL fixture")
    replay.add_argument("--format", choices=["json", "markdown"], default="markdown")
    replay.add_argument("--out", default="", help="Optional JSON output path")
    replay.set_defaults(func=cmd_replay)

    report = sub.add_parser("report", help="Generate audit report from fixture or live URL")
    report.add_argument("fixture", nargs="?", default="", help="Path to JSONL fixture")
    report.add_argument("--url", default="", help="Live diagnostic URL (uses proxy pipeline)")
    report.add_argument("--format", choices=["json", "markdown", "html"], default="markdown")
    report.set_defaults(func=cmd_report)

    certify = sub.add_parser("replay-certify", help="Certify deterministic replay")
    certify.add_argument("fixture", help="Path to JSONL fixture")
    certify.set_defaults(func=cmd_replay_certify)

    bg = sub.add_parser("bad-gateway-diagnose", help="Diagnose 502/bad-gateway (read-only)")
    bg.add_argument("--url", required=True, help="Target HTTPS URL")
    bg.add_argument("--json-only", action="store_true", help="Emit JSON only")
    bg.add_argument("--summary-only", action="store_true", help="Human summary without full JSON")
    bg.set_defaults(func=cmd_bad_gateway_diagnose)

    lh = sub.add_parser(
        "localhost-diagnose",
        help="Diagnose localhost web-app failures (ERR_CONNECTION_REFUSED) — read-only",
    )
    lh.add_argument("--url", default="", help="Preferred form: http://localhost:PORT/path")
    lh.add_argument("--host", default="", help="Loopback host when --url is omitted")
    lh.add_argument("--port", type=int, default=None, help="Port when --url is omitted")
    lh.add_argument("--path", default="", help="URL path when --url is omitted")
    lh.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON report")
    lh.add_argument(
        "--timeout", type=float, default=2.0, help="Per-probe timeout seconds (default 2)"
    )
    lh.add_argument(
        "--include-process", action="store_true", help="Collect process evidence for listener PIDs"
    )
    lh.add_argument("--include-http", action="store_true", help="HTTP probe after TCP success")
    lh.add_argument(
        "--include-proxy-comparison",
        action="store_true",
        help="Compare direct vs proxy-aware HTTP (implies HTTP probe when TCP connects)",
    )
    lh.add_argument(
        "--include-nearby-listeners",
        action="store_true",
        help="Bounded related loopback listeners (no port scan)",
    )
    lh.add_argument("--evidence-out", default="", help="Write full JSON report to path")
    lh.add_argument(
        "--remediation-preview", action="store_true", help="Include PREVIEW/BLOCK remediation items"
    )
    lh.add_argument("--verbose", action="store_true", help="Human summary plus full JSON")
    lh.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="Override loopback-only guard (policy-sensitive; default rejects non-loopback)",
    )
    lh.add_argument("--fixture", default="", help="Optional inject fixture JSON")
    lh.set_defaults(func=cmd_localhost_diagnose)

    lhw = sub.add_parser(
        "localhost-watch",
        help="Watch localhost target for listener/TCP/HTTP transitions (read-only)",
    )
    lhw.add_argument("--url", default="", help="Preferred form: http://localhost:PORT/path")
    lhw.add_argument("--host", default="", help="Loopback host when --url is omitted")
    lhw.add_argument("--port", type=int, default=None, help="Port when --url is omitted")
    lhw.add_argument("--path", default="", help="URL path when --url is omitted")
    lhw.add_argument("--interval", type=float, default=2.0, help="Seconds between polls (min 1)")
    lhw.add_argument("--duration", type=float, default=60.0, help="Watch window seconds")
    lhw.add_argument("--timeout", type=float, default=2.0, help="Per-probe timeout")
    lhw.add_argument("--include-http", action="store_true", help="Include HTTP health in snapshots")
    lhw.add_argument("--jsonl-out", default="", help="Append transition events to JSONL path")
    lhw.set_defaults(func=cmd_localhost_watch)

    ps = sub.add_parser("proxy-status", help="Read-only WinINET/WinHTTP proxy status")
    ps.add_argument("--fixture", default="", help="Optional fixture JSON")
    ps.set_defaults(func=cmd_proxy_status)

    po = sub.add_parser("proxy-owner", help="Detect localhost proxy listener process (JSON)")
    po.add_argument("--fixture", default="", help="Optional fixture JSON")
    po.set_defaults(func=cmd_proxy_owner)

    pd = sub.add_parser("proxy-disable", help="Preview/apply safe HKCU WinINET proxy disable")
    pd.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        help="Preview only (default). Pass false to apply: --dry-run false",
    )
    pd.add_argument("--confirm", default="", help="Typed confirmation token")
    pd.set_defaults(func=cmd_proxy_disable)

    ipv6 = sub.add_parser(
        "ipv6-path",
        help="One-shot IPv6 blackhole investigate (proxy/DNS/Wi-Fi + multi-host probes)",
    )
    ipv6.add_argument(
        "--probe-url",
        default="",
        help="Optional primary HTTPS URL (fallbacks still used)",
    )
    ipv6.add_argument("--timeout", default="8", help="Probe timeout seconds")
    ipv6.add_argument(
        "--prefer-ipv4",
        action="store_true",
        help="Also preview/apply prefer-IPv4 remediation after investigate",
    )
    ipv6.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        help="With --prefer-ipv4: preview only (default). Pass false to apply.",
    )
    ipv6.add_argument(
        "--confirm",
        default="",
        help="With --prefer-ipv4 live apply: PREFER_IPV4_OVER_IPV6",
    )
    ipv6.set_defaults(func=cmd_ipv6_path)

    ipv6s = sub.add_parser(
        "ipv6-path-status",
        help="Read-only multi-host IPv4 vs IPv6 HTTPS path diagnosis",
    )
    ipv6s.add_argument(
        "--probe-url",
        default="",
        help="Optional primary HTTPS URL (default: microsoft + fallbacks)",
    )
    ipv6s.add_argument("--timeout", default="8", help="Probe timeout seconds")
    ipv6s.add_argument(
        "--no-fallback",
        action="store_true",
        help="Probe only --probe-url (no multi-host fallbacks)",
    )
    ipv6s.set_defaults(func=cmd_ipv6_path_status)

    ipv6p = sub.add_parser(
        "ipv6-prefer-ipv4",
        help="Preview/apply prefer-IPv4 (Tcpip6 DisabledComponents 0x20)",
    )
    ipv6p.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        help="Preview only (default). Pass false to apply: --dry-run false",
    )
    ipv6p.add_argument(
        "--confirm",
        default="",
        help="Typed confirmation token (PREFER_IPV4_OVER_IPV6)",
    )
    ipv6p.add_argument(
        "--diagnose",
        action="store_true",
        help="Include dual-stack probe snapshot even on dry-run preview",
    )
    ipv6p.set_defaults(func=cmd_ipv6_prefer_ipv4)

    ipv6r = sub.add_parser(
        "ipv6-restore-preference",
        help="Preview/clear prefer-IPv4 bit to restore IPv6 preference",
    )
    ipv6r.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        help="Preview only (default). Pass false to apply: --dry-run false",
    )
    ipv6r.add_argument(
        "--confirm",
        default="",
        help="Typed confirmation token (RESTORE_IPV6_PREFERENCE)",
    )
    ipv6r.set_defaults(func=cmd_ipv6_restore_preference)

    dns_edge_s = sub.add_parser(
        "dns-edge-status",
        help="Read-only DNS + Edge policy diagnosis for ERR_NAME_NOT_RESOLVED",
    )
    dns_edge_s.add_argument(
        "--interface",
        default="Wi-Fi",
        help="Net adapter alias for DNS read (default: Wi-Fi)",
    )
    dns_edge_s.set_defaults(func=cmd_dns_edge_status)

    dns_edge_f = sub.add_parser(
        "dns-edge-fix",
        help="Preview/apply public-DNS-first + Edge OS-resolver fix",
    )
    dns_edge_f.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="true",
        help="Preview only (default). Pass false to apply: --dry-run false",
    )
    dns_edge_f.add_argument(
        "--confirm",
        default="",
        help="Typed confirmation token (FIX_ERR_NAME_NOT_RESOLVED)",
    )
    dns_edge_f.add_argument(
        "--interface",
        default="Wi-Fi",
        help="Net adapter alias for DNS set (default: Wi-Fi)",
    )
    dns_edge_f.add_argument(
        "--restart-edge",
        action="store_true",
        help="On live apply: stop msedge.exe so Edge reloads DNS/policy",
    )
    dns_edge_f.set_defaults(func=cmd_dns_edge_fix)

    pg = sub.add_parser(
        "proxy-guardian",
        help="Auto-clear dead localhost WinINET proxy (for scheduled guardian)",
    )
    pg.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="false",
        help="Preview only (default false for --once guardian runs)",
    )
    pg.add_argument(
        "--once",
        action="store_true",
        help="Run one guardian check (default behavior)",
    )
    pg.set_defaults(func=cmd_proxy_guardian)

    af = sub.add_parser(
        "auto-fix-chatgpt",
        help="Auto-fix ChatGPT connectivity: proxy guardian, diagnose, LOW-risk remediations",
    )
    af.add_argument(
        "--dry-run",
        nargs="?",
        const="true",
        default="false",
        help="Preview only. Pass true for dry-run: --dry-run true",
    )
    af.add_argument(
        "--confirm",
        default="",
        help="Typed confirmation for LOW-risk apply (default: APPLY_CHATGPT_LOW_RISK when live)",
    )
    af.add_argument(
        "--url",
        default="https://chatgpt.com",
        help="HTTPS URL for bad-gateway diagnose step",
    )
    af.add_argument(
        "--skip-proxy-auto-fix",
        action="store_true",
        help="Skip proxy-guardian step (use when auto-fix-proxy.ps1 already ran)",
    )
    af.add_argument(
        "--skip-guardian-install",
        action="store_true",
        help="Reserved for PS orchestrator; guardian install is handled by auto-fix-proxy.ps1",
    )
    af.set_defaults(func=cmd_auto_fix_chatgpt)

    pw = sub.add_parser("proxy-watch", help="Poll WinINET proxy for drift (read-only)")
    pw.add_argument("--duration", default="900", help="Watch duration seconds")
    pw.add_argument("--interval", default="2", help="Poll interval seconds")
    pw.add_argument("--fixture", default="", help="Optional fixture JSON")
    pw.add_argument("--format", choices=("json", "human"), default="json", help="Output format")
    pw.add_argument("--json-also", action="store_true", help="With --format human, also emit JSON")
    pw.add_argument("--timeout", default="5", help="Health probe timeout seconds")
    pw.add_argument("--no-direct-probe", action="store_true", help="Skip direct HTTPS probes")
    pw.add_argument("--no-proxy-probe", action="store_true", help="Skip proxy forwarding probes")
    pw.add_argument(
        "--coalesce-ms",
        default="1000",
        help="Merge rapid registry sub-events within this window (200-5000 ms)",
    )
    pw.set_defaults(func=cmd_proxy_watch)

    preplay = sub.add_parser("proxy-replay", help="Replay proxy-watch JSONL through state machine")
    preplay.add_argument("--input", required=True, help="JSONL fixture or audit log path")
    preplay.add_argument(
        "--coalesce-ms",
        default="1000",
        help="Coalescing window in milliseconds (200-5000)",
    )
    preplay.add_argument(
        "--format", choices=("json", "human"), default="json", help="Output format"
    )
    preplay.add_argument(
        "--json-also", action="store_true", help="With --format human, also emit JSON"
    )
    preplay.set_defaults(func=cmd_proxy_replay)

    replay_demo = sub.add_parser(
        "replay-demo",
        help="Alias for proxy-replay — deterministic fixture replay demo",
    )
    replay_demo.add_argument("--input", required=True, help="JSONL fixture or audit log path")
    replay_demo.add_argument(
        "--coalesce-ms",
        default="1000",
        help="Coalescing window in milliseconds (200-5000)",
    )
    replay_demo.add_argument(
        "--format", choices=("json", "human"), default="json", help="Output format"
    )
    replay_demo.add_argument(
        "--json-also", action="store_true", help="With --format human, also emit JSON"
    )
    replay_demo.set_defaults(func=cmd_proxy_replay)

    ph = sub.add_parser("proxy-health", help="Localhost proxy health check (read-only)")
    ph.add_argument("--host", default="", help="Override localhost host")
    ph.add_argument("--port", default="", help="Override localhost port")
    ph.add_argument("--url", action="append", default=[], help="Test URL (repeatable)")
    ph.add_argument("--timeout", default="5", help="Probe timeout seconds")
    ph.add_argument("--json", action="store_true", help="Emit JSON only")
    ph.add_argument("--json-also", action="store_true", help="Emit JSON after summary")
    ph.add_argument("--fixture", default="", help="Optional fixture JSON")
    ph.add_argument("--no-direct-probe", action="store_true", help="Skip direct HTTPS probes")
    ph.add_argument("--no-proxy-probe", action="store_true", help="Skip proxy forwarding probes")
    ph.set_defaults(func=cmd_proxy_health)

    prpt = sub.add_parser("proxy-report", help="Structured incident-style JSON report")
    prpt.add_argument("--url", default="", help="Optional URL for proof section")
    prpt.add_argument("--fixture", default="", help="Optional fixture JSON")
    prpt.add_argument(
        "--include-principles",
        action="store_true",
        help="Include evidence chain, principle compliance, and safe remediation sections",
    )
    prpt.set_defaults(func=cmd_proxy_report)

    principles = sub.add_parser("principles", help="Epistemic principle contracts")
    principles_sub = principles.add_subparsers(dest="principles_cmd", required=True)
    p_explain = principles_sub.add_parser("explain", help="List the four epistemic principles")
    p_explain.set_defaults(func=cmd_principles_explain)
    p_validate = principles_sub.add_parser("validate", help="Validate fixture against principles")
    p_validate.add_argument(
        "--fixture",
        default="",
        help="Fixture JSON path (default: case_studies/cs1_wininet_proxy_drift/fixture.json)",
    )
    p_validate.set_defaults(func=cmd_principles_validate)

    diag = sub.add_parser("diagnose", help="Structured proof diagnosis")
    diag.add_argument("--proof", action="store_true", help="Run proof envelope")
    diag.add_argument(
        "--principles",
        action="store_true",
        help="Include principle compliance sections in output",
    )
    diag.add_argument(
        "--decision-context",
        action="store_true",
        help="Attach stakeholder/timing/coordination envelope (does not change proof)",
    )
    diag.add_argument(
        "--timezone",
        default="",
        help="IANA timezone for timing evaluation (default UTC; e.g. Asia/Taipei)",
    )
    diag.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Output format when --decision-context is set (default json)",
    )
    diag.add_argument("--url", default="", help="Optional URL for network probes")
    diag.add_argument("--fixture", default="", help="Optional fixture JSON")
    diag.set_defaults(func=cmd_diagnose)

    pa = sub.add_parser("proxy-attribution", help="Read-only proxy listener attribution")
    pa.set_defaults(func=cmd_proxy_attribution)

    pwa = sub.add_parser(
        "proxy-writer-attribution",
        help="Proxy registry writer attribution with Sysmon E13 fusion (read-only)",
    )
    pwa.add_argument("--fixture", default="", help="Optional fixture JSON for replay")
    pwa.set_defaults(func=cmd_proxy_writer_attribution)

    tls = sub.add_parser(
        "tls-proof", help="TLS certificate contrast direct vs proxied path (read-only)"
    )
    tls.add_argument("--url", required=True, help="Target HTTPS URL")
    tls.add_argument("--fixture", default="", help="Optional fixture JSON for replay")
    tls.set_defaults(func=cmd_tls_proof)

    wr = sub.add_parser("website-risk", help="Website risk heuristic scoring (read-only)")
    wr.add_argument("--url", required=True, help="Target URL")
    wr.add_argument("--fixture", default="", help="Optional fixture JSON for replay")
    wr.set_defaults(func=cmd_website_risk)

    er = sub.add_parser(
        "evidence-report",
        help="Merged evidence timeline report (JSONL/Markdown/HTML, preview-only)",
    )
    er.add_argument("--executive", action="store_true", help="Executive portfolio evidence report")
    er.add_argument("--risk-register", default="", help="Risk register JSON for executive report")
    er.add_argument(
        "--cloud-fixture", default="", help="Cloud governance fixture for executive report"
    )
    er.add_argument("--finops-fixture", default="", help="FinOps fixture for executive report")
    er.add_argument("--audit-dir", default="", help="Optional audit dir for executive KPI rollup")
    er.add_argument(
        "--latest", action="store_true", help="Latest proxy path diagnosis report (markdown)"
    )
    er.add_argument(
        "--analytics", action="store_true", help="Endpoint evidence analytics report (markdown)"
    )
    er.add_argument("--url", default="", help="Target URL for network proof (legacy merged report)")
    er.add_argument("--fixture", default="", help="Optional fixture JSON for replay")
    er.add_argument("--format", choices=["json", "jsonl", "markdown", "html"], default="markdown")
    er.add_argument("--out", default="", help="Optional output file path")
    er.add_argument(
        "--no-direct-probe", action="store_true", help="With --latest: skip direct HTTPS probes"
    )
    er.add_argument(
        "--no-proxy-probe", action="store_true", help="With --latest: skip proxy forwarding probes"
    )
    er.set_defaults(func=cmd_evidence_report)

    pp = sub.add_parser("proxy-proof", help="Direct vs proxied path proof (read-only)")
    pp.add_argument("--url", required=True, help="Target HTTPS URL")
    pp.set_defaults(func=cmd_proxy_proof)

    pt = sub.add_parser("proxy-timeline", help="Build incident timeline from proxy state or audit")
    pt.add_argument("--url", default="", help="Optional URL for proof probes")
    pt.add_argument("--audit", action="store_true", help="Prefer .audit/ timeline when available")
    pt.add_argument("--audit-only", action="store_true", help="Read .audit/ only")
    pt.set_defaults(func=cmd_proxy_timeline)

    audit = sub.add_parser("audit", help="Audit chain operations")
    audit_sub = audit.add_subparsers(dest="audit_cmd", required=True)
    verify = audit_sub.add_parser("verify", help="Verify hash chain integrity")
    verify.add_argument("audit_file", help="Path to audit JSONL")
    verify.add_argument(
        "--check-tip",
        action="store_true",
        help="Also compare sibling tip anchor ({stem}.tip.json) to the chain tip",
    )
    verify.add_argument(
        "--require-tip",
        action="store_true",
        help="Fail if tip anchor is missing (implies --check-tip)",
    )
    verify.add_argument(
        "--tip-path",
        default="",
        help="Optional tip anchor path (default: sibling {stem}.tip.json)",
    )
    verify.set_defaults(func=cmd_audit_verify)

    ra = sub.add_parser("risk-assess", help="Technology risk assessment from case fixture (JSON)")
    ra.add_argument("--fixture", required=True, help="Case study fixture JSON path or name")
    ra.set_defaults(func=cmd_risk_assess)

    ct = sub.add_parser("control-test", help="Run control tests against case fixture (JSON)")
    ct.add_argument("--fixture", required=True, help="Case study fixture JSON path or name")
    ct.set_defaults(func=cmd_control_test)

    gr = sub.add_parser(
        "governance-report", help="Governance / management report (fixture or audit-dir)"
    )
    gr.add_argument("--fixture", default="", help="Case study fixture JSON path or name")
    gr.add_argument("--audit-dir", default="", help="Audit JSONL directory for audit-backed report")
    gr.add_argument("--risk-register", default="", help="Optional risk register JSON path")
    gr.add_argument(
        "--include-decision-context",
        action="store_true",
        help="Enrich fixture report with stakeholder/timing/coordination sections",
    )
    gr.add_argument("--timezone", default="", help="IANA timezone when including decision context")
    gr.add_argument(
        "--audit-dir-kpi",
        default="",
        dest="audit_dir_kpi",
        help="Optional audit dir for coordination KPI rollup",
    )
    gr.add_argument("--format", choices=["json", "markdown", "html"], default="json")
    gr.set_defaults(func=cmd_governance_report)

    sr = sub.add_parser(
        "stakeholder-resolve", help="Resolve stakeholder roles for a case (roles/config only)"
    )
    sr.add_argument("--case-id", required=True, help="Case / incident id")
    sr.add_argument("--classification", default="", help="Primary classification label")
    sr.add_argument("--policy-outcome", default="", help="Policy outcome string")
    sr.add_argument("--config", default="", help="Optional stakeholder config JSON path")
    sr.add_argument("--requires-approval", action="store_true", default=True)
    sr.set_defaults(func=cmd_stakeholder_resolve)

    te = sub.add_parser("timing-evaluate", help="Evaluate timing/SLA/window for a case (read-only)")
    te.add_argument("--case-id", required=True, help="Case / incident id")
    te.add_argument(
        "--detected-at", default="", dest="detected_at", help="ISO8601 detection time (UTC)"
    )
    te.add_argument("--timezone", default="", help="IANA timezone (default UTC)")
    te.add_argument("--classification", default="", help="Optional classification for urgency")
    te.add_argument("--maintenance-window-required", action="store_true")
    te.add_argument("--change-freeze", action="store_true")
    te.set_defaults(func=cmd_timing_evaluate)

    de = sub.add_parser("decision-explain", help="Explain stored decision-context envelope")
    de.add_argument("--case-id", required=True, help="Case / incident id")
    de.add_argument("--format", choices=["json", "text"], default="json")
    de.set_defaults(func=cmd_decision_explain)

    rks = sub.add_parser("risk-kpi-summary", help="Risk KPI rollup from audit JSONL (read-only)")
    rks.add_argument(
        "--audit-dir", default="tests/fixtures/risk_analytics/audit_sample", help="Audit directory"
    )
    rks.add_argument("--format", choices=["json", "markdown"], default="json")
    rks.set_defaults(func=cmd_risk_kpi_summary)

    rm = sub.add_parser("risk-matrix", help="Risk matrix heat-map export (read-only)")
    rm_sub = rm.add_subparsers(dest="risk_matrix_cmd", required=True)
    rm_export = rm_sub.add_parser("export", help="Export risk matrix JSON or CSV")
    rm_export.add_argument(
        "--register",
        default="tests/fixtures/risk_register/sample_risk_register.json",
        help="Risk register JSON path",
    )
    rm_export.add_argument("--format", choices=["json", "csv"], default="json")
    rm_export.add_argument("--out", default="", help="Optional output file path")
    rm_export.set_defaults(func=cmd_risk_matrix)

    cr = sub.add_parser(
        "cloud-recommendations",
        help="Summarize mock cloud governance recommendations (read-only)",
    )
    cr_sub = cr.add_subparsers(dest="cloud_recommendations_cmd", required=True)
    cr_sum = cr_sub.add_parser("summarize", help="Summarize recommendations by pillar/provider")
    cr_sum.add_argument(
        "--fixture",
        default="tests/fixtures/cloud_governance/mock_recommendations.json",
        help="Cloud governance fixture JSON",
    )
    cr_sum.add_argument("--format", choices=["json", "markdown"], default="json")
    cr_sum.set_defaults(func=cmd_cloud_recommendations)

    fo = sub.add_parser("finops", help="FinOps mock cost export (read-only)")
    fo_sub = fo.add_subparsers(dest="finops_cmd", required=True)
    fo_export = fo_sub.add_parser("export", help="Export FinOps cost facts")
    fo_export.add_argument(
        "--fixture",
        default="tests/fixtures/finops/mock_costs.json",
        help="FinOps cost fixture JSON",
    )
    fo_export.add_argument("--out-dir", default="", help="Optional output directory")
    fo_export.add_argument("--format", choices=["json", "csv", "both"], default="json")
    fo_export.set_defaults(func=cmd_finops_export)

    ans = sub.add_parser(
        "analytics-summary", help="Endpoint evidence analytics summary (read-only)"
    )
    ans.add_argument("--input", default="", help="Audit JSONL file or directory (default: .audit)")
    ans.add_argument("--fixture", default="", help="Optional fixture JSON for deterministic replay")
    ans.add_argument(
        "--audit-dir", default=".audit", help="Legacy platform audit dir (with --legacy-platform)"
    )
    ans.add_argument(
        "--legacy-platform",
        action="store_true",
        help="Use legacy platform_core risk analytics summarizer",
    )
    ans.add_argument("--format", choices=["json", "markdown", "human"], default="human")
    ans.add_argument("--json", action="store_true", help="Emit JSON (same as --format json)")
    ans.add_argument(
        "--bucket", choices=["day", "hour"], default="day", help="Timeline bucket granularity"
    )
    ans.add_argument("--limit-processes", default="10", help="Top listener process limit")
    ans.set_defaults(func=cmd_analytics_summary)

    aex = sub.add_parser("analytics-export", help="Export endpoint analytics JSON/CSV (read-only)")
    aex.add_argument("--input", default="", help="Audit JSONL file or directory")
    aex.add_argument("--fixture", default="", help="Optional fixture JSON")
    aex.add_argument("--out", default="reports/analytics", help="Output directory")
    aex.add_argument(
        "--format", choices=["json", "csv", "both"], default="both", help="Export format"
    )
    aex.add_argument("--bucket", choices=["day", "hour"], default="day")
    aex.add_argument("--limit-processes", default="10")
    aex.set_defaults(func=cmd_analytics_export)

    pbi = sub.add_parser(
        "analytics-export-powerbi",
        help="Export Power BI-ready CSV tables from audit JSONL (read-only)",
    )
    pbi.add_argument(
        "--audit-dir",
        default="tests/fixtures/risk_analytics/audit_sample",
        help="Audit JSONL directory",
    )
    pbi.add_argument(
        "--out-dir",
        default="analytics/powerbi/data",
        help="Output directory for CSV files",
    )
    pbi.add_argument(
        "--portfolio-sample",
        action="store_true",
        help="Write deterministic portfolio sample CSVs (ignores audit-dir)",
    )
    pbi.add_argument(
        "--include-seed",
        action="store_true",
        help="Merge portfolio seed rows when audit dir is sparse",
    )
    pbi.set_defaults(func=cmd_analytics_export_powerbi)

    export_pbi = sub.add_parser(
        "export-powerbi",
        help="Alias for analytics-export-powerbi (star-schema CSV export)",
    )
    export_pbi.add_argument("--audit-dir", default="tests/fixtures/risk_analytics/audit_sample")
    export_pbi.add_argument("--out-dir", default="analytics/powerbi/sample_csv")
    export_pbi.add_argument("--portfolio-sample", action="store_true")
    export_pbi.add_argument("--include-seed", action="store_true")
    export_pbi.set_defaults(func=cmd_analytics_export_powerbi)

    star = sub.add_parser(
        "powerbi-export",
        help="Export Power BI star schema semantic model pack (read-only)",
    )
    star.add_argument(
        "--audit-dir",
        default="tests/fixtures/risk_analytics/audit_sample",
        help="Audit JSONL directory",
    )
    star.add_argument(
        "--out-dir",
        default="examples/powerbi/export",
        help="Output directory for star schema CSV files",
    )
    star.add_argument(
        "--no-seed",
        action="store_true",
        help="Do not merge portfolio seed rows (audit-only export)",
    )
    star.add_argument("--risk-register", default="", help="Optional risk register JSON path")
    star.add_argument("--cloud-fixture", default="", help="Optional cloud governance fixture path")
    star.add_argument("--finops-fixture", default="", help="Optional FinOps fixture path")
    star.set_defaults(func=cmd_powerbi_export)

    demo = sub.add_parser("demo", help="Golden fixture demo (read-only)")
    demo.set_defaults(func=cmd_demo)

    rd = sub.add_parser("reviewer-demo", help="Deterministic reviewer walkthrough (read-only)")
    rd.add_argument("--mode", choices=["big4", "faang", "mixed"], default="mixed")
    rd.add_argument("--out", default="", help="Optional demo-output directory for audit artifacts")
    rd.add_argument("--json", action="store_true", help="Emit summary JSON after walkthrough")
    rd.set_defaults(func=cmd_reviewer_demo)

    fs = sub.add_parser("fleet-simulate", help="Synthetic fleet audit JSONL (read-only)")
    fs.add_argument("--scenario", default="mixed_proxy_failures")
    fs.add_argument("--endpoints", default="100")
    fs.add_argument("--seed", default="42")
    fs.add_argument("--out", default="examples/fleet/audit_sample")
    fs.set_defaults(func=cmd_fleet_simulate)

    fb = sub.add_parser("fleet-benchmark", help="Fleet performance and classification benchmark")
    fb.add_argument("--scenario", default="mixed_proxy_failures")
    fb.add_argument("--endpoints", default="100")
    fb.add_argument("--seed", default="42")
    fb.add_argument("--format", choices=["json", "markdown"], default="json")
    fb.add_argument("--out", default="", help="Output markdown path when --format markdown")
    fb.set_defaults(func=cmd_fleet_benchmark)

    be = sub.add_parser(
        "browser-evidence", help="Playwright browser evidence package (screenshot + HAR)"
    )
    be.add_argument("--url", default="", help="URL to capture")
    be.add_argument(
        "--fixture", default="", help="Load fixture package JSON instead of live browser"
    )
    be.add_argument("--out", default="browser_evidence_out", help="Output directory for captures")
    be.add_argument("--headed", action="store_true", help="Run browser headed (not headless)")
    be.add_argument("--format", choices=["json", "package"], default="json")
    be.set_defaults(func=cmd_browser_evidence)

    bd = sub.add_parser(
        "browser-diff",
        help="Normal vs InPrivate browser-profile differential (privacy-preserving, read-only)",
    )
    bd.add_argument("url", nargs="?", default="", help="Target URL (e.g. https://www.104.com.tw/)")
    bd.add_argument("--browser", default="auto", choices=["edge", "chrome", "auto"])
    bd.add_argument(
        "--proof", action="store_true", help="Emphasize proof ladder / request stronger evidence"
    )
    bd.add_argument("--fixture", default="", help="Fixture JSON for offline replay")
    bd.add_argument("--import-normal-har", default="", help="HAR from normal browser profile")
    bd.add_argument("--import-private-har", default="", help="HAR from InPrivate/Incognito")
    bd.add_argument("--format", choices=["json", "text"], default="json")
    bd.set_defaults(func=cmd_browser_diff)

    bp = sub.add_parser(
        "browser-profile", help="Inspect/repair-preview Chromium profiles (metadata only)"
    )
    bp_sub = bp.add_subparsers(dest="browser_profile_cmd", required=True)
    bp_ins = bp_sub.add_parser("inspect", help="List profiles / installation / policies")
    bp_ins.add_argument("--browser", default="auto", choices=["edge", "chrome", "auto"])
    bp_ins.set_defaults(func=cmd_browser_profile)
    bp_ss = bp_sub.add_parser("site-state", help="Cookie count/meta + storage flags for a domain")
    bp_ss.add_argument("domain", help="Domain e.g. 104.com.tw")
    bp_ss.add_argument("--browser", default="auto", choices=["edge", "chrome", "auto"])
    bp_ss.set_defaults(func=cmd_browser_profile)
    bp_rp = bp_sub.add_parser("repair-preview", help="Preview site-scoped cleanup (never applies)")
    bp_rp.add_argument("domain", help="Domain e.g. 104.com.tw")
    bp_rp.add_argument("--browser", default="auto", choices=["edge", "chrome", "auto"])
    bp_rp.set_defaults(func=cmd_browser_profile)
    bp_ra = bp_sub.add_parser(
        "repair-apply", help="Gated apply (requires --confirm; may be unimplemented)"
    )
    bp_ra.add_argument("preview_id", help="Preview id from repair-preview")
    bp_ra.add_argument("--confirm", default="", help="BROWSER_SITE_REPAIR_APPLY")
    bp_ra.set_defaults(func=cmd_browser_profile)

    cb = sub.add_parser("classifier-benchmark", help="Offline classifier evaluation harness")
    cb.add_argument("--cases", default="examples/evaluation/classifier_benchmark_sample.json")
    cb.add_argument("--format", choices=["json", "markdown"], default="json")
    cb.set_defaults(func=cmd_classifier_benchmark)

    rb = sub.add_parser("replay-benchmark", help="Evidence replay determinism benchmark")
    rb.add_argument("--cases", default="tests/fixtures/evaluation/replay_cases.jsonl")
    rb.add_argument("--replay-count", default="2")
    rb.add_argument("--format", choices=["json", "markdown"], default="json")
    rb.set_defaults(func=cmd_replay_benchmark)

    ae = sub.add_parser(
        "ai-eval", help="Fixture-based AI evals feedback loop (no live model calls)"
    )
    ae.add_argument("--cases", default="examples/ai_evals/support_bot_cases.json")
    ae.add_argument("--format", choices=["json", "markdown"], default="markdown")
    ae.set_defaults(func=cmd_ai_eval)

    li = sub.add_parser("lan-inventory", help="LAN asset inventory (read-only)")
    li.add_argument("--fixture", default="", help="Fixture JSON for offline inventory")
    li.add_argument("--subnet", default="", help="Subnet override for display")
    li.add_argument("--json-only", action="store_true", help="JSON output only")
    li.set_defaults(func=cmd_lan_inventory)

    lw = sub.add_parser("lan-watch", help="Poll LAN neighbors and append JSONL (read-only)")
    lw.add_argument("--duration", default="60", help="Watch duration seconds")
    lw.add_argument("--interval", default="10", help="Poll interval seconds")
    lw.add_argument("--fixture", default="", help="Fixture with watch_sequence")
    lw.add_argument("--audit-path", default=".audit/lan-watch.jsonl", help="JSONL output path")
    lw.add_argument("--mdns", action="store_true", help="Include brief mDNS sample each tick")
    lw.set_defaults(func=cmd_lan_watch)

    lms = sub.add_parser("lan-mdns-summary", help="mDNS discovery summary (read-only)")
    lms.add_argument("--duration", default="5", help="Listen duration seconds")
    lms.add_argument("--fixture", default="", help="Fixture inject")
    lms.set_defaults(func=cmd_lan_mdns_summary)

    lss = sub.add_parser("lan-ssdp-summary", help="SSDP/UPnP discovery summary (read-only)")
    lss.add_argument("--duration", default="5", help="Probe duration seconds")
    lss.add_argument("--fixture", default="", help="Fixture inject")
    lss.set_defaults(func=cmd_lan_ssdp_summary)

    lpr = sub.add_parser("lan-privacy-report", help="LAN privacy evidence report")
    lpr.add_argument("--fixture", default="", help="Bundle or scenario fixture")
    lpr.add_argument("--watch-log", default="", help="lan-watch JSONL path")
    lpr.add_argument("--format", choices=["json", "markdown", "both"], default="json")
    lpr.add_argument("--out-dir", default="", help="Write report files to directory")
    lpr.set_defaults(func=cmd_lan_privacy_report)

    lrs = sub.add_parser("lan-risk-score", help="Privacy risk score (transparent formula)")
    lrs.add_argument("--fixture", required=True, help="Bundle fixture path")
    lrs.set_defaults(func=cmd_lan_risk_score)

    lct = sub.add_parser("lan-control-test", help="CTRL-LAN control matrix evaluation")
    lct.add_argument("--fixture", required=True, help="Bundle fixture path")
    lct.set_defaults(func=cmd_lan_control_test)

    ri = sub.add_parser("router-import", help="Import router logs to normalized JSONL")
    ri.add_argument("--type", required=True, choices=["dns", "firewall", "dhcp", "devices"])
    ri.add_argument("--input", required=True, help="Router export file path")
    ri.add_argument("--out", required=True, help="Output JSONL path")
    ri.add_argument("--fixture", default="", help="Inject events instead of parsing input")
    ri.set_defaults(func=cmd_router_import)

    rc = sub.add_parser("router-correlate", help="Correlate host LAN log with router JSONL")
    rc.add_argument("--host-log", required=True, help="lan-watch JSONL path")
    rc.add_argument("--router-log", required=True, help="Router evidence JSONL path")
    rc.set_defaults(func=cmd_router_correlate)

    rer = sub.add_parser("risk-executive-report", help="Executive LAN technology risk report")
    rer.add_argument("--fixture", required=True, help="Executive bundle fixture")
    rer.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    rer.add_argument("--out-dir", default="", help="Output directory")
    rer.set_defaults(func=cmd_risk_executive_report)

    agent = sub.add_parser(
        "agent",
        help="Read-only local endpoint agent (evidence spool; no remediation)",
    )
    agent_sub = agent.add_subparsers(dest="agent_cmd", required=True)

    def _add_agent_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--spool",
            default="",
            help="Agent JSONL spool path (default: .audit/agent-spool.jsonl)",
        )
        p.add_argument(
            "--fixture",
            default="",
            help="Evidence bundle fixture (skips live collection)",
        )
        p.add_argument(
            "--os-family",
            default="",
            choices=["", "windows", "linux", "darwin", "unknown"],
            help="Force OS family for evidence collection (tests/fixtures)",
        )

    agent_once = agent_sub.add_parser("once", help="One read-only evidence collection cycle")
    _add_agent_common(agent_once)
    agent_once.set_defaults(func=cmd_agent_once)

    agent_run = agent_sub.add_parser("run", help="Loop read-only collection until Ctrl+C")
    _add_agent_common(agent_run)
    agent_run.add_argument("--interval", default="30", help="Seconds between cycles (min 5)")
    agent_run.add_argument(
        "--max-cycles",
        default="",
        help="Optional max cycles (for tests); default runs until interrupt",
    )
    agent_run.set_defaults(func=cmd_agent_run)

    agent_health = agent_sub.add_parser("health", help="Agent health and optional backend probe")
    agent_health.add_argument("--spool", default="", help="Agent JSONL spool path")
    agent_health.add_argument(
        "--api",
        default="",
        help="Optional backend base URL for GET /health (read-only)",
    )
    agent_health.set_defaults(func=cmd_agent_health)

    agent_spool = agent_sub.add_parser("spool-status", help="Inspect agent JSONL spool depth")
    agent_spool.add_argument("--spool", default="", help="Agent JSONL spool path")
    agent_spool.set_defaults(func=cmd_agent_spool_status)

    args = parser.parse_args(argv)
    return int(args.func(args))


def console_main() -> None:
    """Setuptools console script entry point for ``wnrt``."""
    raise SystemExit(main(prog="wnrt"))


if __name__ == "__main__":
    raise SystemExit(main())

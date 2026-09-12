"""Endpoint Network Evidence & Risk orchestrator — read-only by default.

Module responsibility:
    Coordinate the full endpoint evidence pipeline: proxy-writer attribution,
    network proof, TLS MITM risk, website risk, evidence timeline merge, and
    confidence model calculation.  Assembles the results into a single
    structured package suitable for governance reporting and control testing.

System placement:
    Entry point for ``diagnostics/evidence/__init__.py`` and the CLI
    ``evidence-assess`` / ``evidence-report`` commands.  Integrates with
    ``diagnostics/proxy/runner.py`` (``run_proxy_timeline``) for timeline
    construction and with ``src.platform_core`` modules for proof, TLS,
    website risk, and confidence scoring.

Key invariants:
    * ``run_evidence_assessment`` always includes ``safety_notes`` that clarify
      this is an evidence toolkit, not antivirus/phishing protection.
    * ``confidence_model`` is computed twice: once with an empty payload for
      structure, then recalculated over the full package to incorporate all
      cross-signal weights.
    * TLS and website-risk steps are individually optional (``include_tls``,
      ``include_website_risk``) to support partial runs in test or CI contexts.

Side effects:
    Spawns network probes, subprocesses, and registry reads when fixture
    injection is absent.  No filesystem writes within these functions.

Failure modes:
    Individual sub-step failures (e.g. TLS negotiation error) produce a
    partial package rather than aborting; the failed step's field will be
    ``None`` or empty.  Callers should check sub-dict presence before
    rendering.
"""

from __future__ import annotations

import uuid
from typing import Any

from src.platform_core.attribution.writer_engine import run_proxy_writer_attribution
from src.platform_core.evidence_report.confidence_model import build_confidence_entries
from src.platform_core.evidence_report.generator import generate_evidence_report
from src.platform_core.evidence_report.timeline_merger import merge_evidence_timeline
from src.platform_core.proof.engine import run_proof_engine
from src.platform_core.tls.engine import run_tls_proof
from src.platform_core.website_risk.engine import run_website_risk
from windows_network_toolkit.diagnostics.proxy.runner import run_proxy_timeline


def run_evidence_assessment(
    url: str,
    *,
    include_tls: bool = True,
    include_website_risk: bool = True,
    inject_writer: dict[str, Any] | None = None,
    inject_proof: dict[str, Any] | None = None,
    inject_tls: dict[str, Any] | None = None,
    inject_website: dict[str, Any] | None = None,
    inject_sysmon: list[dict[str, Any]] | None = None,
    user_actions: list[dict[str, Any]] | None = None,
    run: Any = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Build a full evidence package: attribution, proof, TLS, website risk, merged timeline.

    Coordinates the full evidence-pipeline for *url*: proxy-writer attribution,
    network proof, optional TLS MITM analysis, optional website risk scoring,
    proxy timeline construction, and evidence timeline merge.

    Args:
        url: Target URL under assessment.
        include_tls: When ``True``, runs ``run_tls_proof`` and includes TLS
            MITM risk in the package.
        include_website_risk: When ``True``, runs ``run_website_risk``.
        inject_writer: Fixture for ``run_proxy_writer_attribution``.
        inject_proof: Fixture for ``run_proof_engine``.
        inject_tls: Fixture for ``run_tls_proof``.
        inject_website: Fixture for ``run_website_risk``.
        inject_sysmon: Fixture Sysmon entries for the writer attribution step.
        user_actions: Optional operator-annotated action entries to merge
            into the evidence timeline.
        run: Injectable ``subprocess.run`` for testing.
        timeout: Per-probe wall-clock timeout in seconds (default 20 s to
            allow TLS handshake).

    Returns:
        Evidence package dict with keys: ``incident_id``, ``url``,
        ``executive_summary``, ``proxy_writer_attribution``, ``proof_results``,
        ``tls_proof``, ``website_risk``, ``timeline``, ``confidence_model``,
        ``remediation_preview``, ``safety_notes``.

    Side effects:
        Spawns subprocesses and network probes when fixtures are absent.

    Audit note:
        The ``remediation_preview`` field is derived from the proxy timeline
        and must not be treated as an execution instruction.  ``safety_notes``
        must be preserved intact in all downstream rendering.
    """
    incident_id = f"enr-{uuid.uuid4().hex[:12]}"

    writer = run_proxy_writer_attribution(
        run=run,
        timeout=timeout,
        inject=inject_writer,
        inject_sysmon=inject_sysmon,
    )
    dead = writer.snapshot.classification.value == "DEAD_PROXY_CONFIG"
    proof = run_proof_engine(
        url,
        proxy_server=writer.snapshot.proxy_state.wininet_proxy_server or None,
        dead_localhost_proxy=dead,
        inject=inject_proof,
        run=run,
        timeout=timeout,
    )

    tls = run_tls_proof(url, inject=inject_tls, run=run, timeout=timeout) if include_tls else None
    website = (
        run_website_risk(url, inject=inject_website, run=run, timeout=timeout)
        if include_website_risk
        else None
    )

    proof_dict = proof.to_dict()
    base_timeline = run_proxy_timeline(
        url,
        inject_attribution=writer.snapshot.to_dict(),
        inject_proof=inject_proof or proof_dict,
        run=run,
        timeout=timeout,
    )

    timeline = merge_evidence_timeline(
        incident_id=incident_id,
        proxy_writer=writer.to_dict(),
        proof_results=proof.to_dict(),
        tls_proof=tls.to_dict() if tls else None,
        website_risk=website.to_dict() if website else None,
        user_actions=user_actions,
        existing_entries=base_timeline.get("timeline"),
    )

    summary_parts = [
        f"Proxy classification: {writer.classification}.",
        f"Network proof: {proof.outcome.value}.",
    ]
    if tls:
        summary_parts.append(f"TLS MITM risk: {tls.mitm_risk_level.value}.")
    if website:
        summary_parts.append(f"Website risk: {website.risk_level.value}.")

    package = {
        "incident_id": incident_id,
        "url": url,
        "executive_summary": " ".join(summary_parts),
        "proxy_writer_attribution": writer.to_dict(),
        "proof_results": proof.to_dict(),
        "tls_proof": tls.to_dict() if tls else None,
        "website_risk": website.to_dict() if website else None,
        "timeline": timeline,
        "confidence_model": [e.to_dict() for e in build_confidence_entries({})],
        "remediation_preview": base_timeline.get("remediation_preview"),
        "safety_notes": [
            "Preview-only — no silent registry modification or process termination.",
            "Evidence toolkit — not antivirus or phishing protection.",
        ],
    }
    package["confidence_model"] = [e.to_dict() for e in build_confidence_entries(package)]
    return package


def run_evidence_report(
    url: str,
    *,
    fmt: str = "markdown",
    **kwargs: Any,
) -> str:
    """Generate a formatted evidence report string for *url*.

    Calls ``run_evidence_assessment`` with all provided keyword arguments,
    then passes the resulting package to ``generate_evidence_report`` for
    rendering.

    Args:
        url: Target URL under assessment.
        fmt: Output format passed to ``generate_evidence_report``; typically
            ``"markdown"`` or ``"json"``.
        **kwargs: Forwarded to ``run_evidence_assessment`` (e.g. fixture
            injections, ``timeout``, ``include_tls``).

    Returns:
        Formatted report string.  Content includes executive summary, timeline,
        proof results, and safety notes.
    """
    package = run_evidence_assessment(url, **kwargs)
    return generate_evidence_report(package, fmt=fmt)  # type: ignore[arg-type]

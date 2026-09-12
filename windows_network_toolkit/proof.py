"""Structured proof envelope — observation, hypothesis, proof attempts, conclusion.

Module responsibility:
    Constructs a ``ProofResult`` that walks the
    Observation → Hypothesis → Proof → Conclusion chain for a proxy-state
    diagnosis.  Optionally enriches the result with governance envelope and
    principle-compliance metadata for operator-facing report rendering.

System placement:
    Called by ``report.py`` (``build_proxy_report``) and the ``diagnose`` CLI
    command.  Uses ``classify_from_live``, ``detect_proxy_owner``, and
    ``collect_proxy_state_model`` for live evidence; accepts ``inject`` dicts for
    deterministic test execution.

Key invariants:
    ``limitations[]`` in the returned ``ProofResult`` must always include
    statements clarifying that the proof does not confirm malware or MITM.
    Observation is not proof; confidence scores are ordinal estimates only.

Side effects:
    When ``inject`` is ``None``: reads HKCU WinINET/WinHTTP registry keys and
    probes open TCP ports.  If ``url`` is provided, issues network probes via
    ``run_proof_engine``.

Failure modes:
    Registry or network errors propagate from the underlying collectors.
    Malformed ``inject`` dicts raise ``KeyError`` / ``TypeError`` from dataclass
    construction.

Engineering Notes:
    Confidence thresholds (0.92 for confirmed dead proxy, 0.72 for WinINET/
    WinHTTP mismatch) are heuristics informed by field data — not statistical
    bounds.  They must not be interpreted as probability-of-attack values.
"""

from __future__ import annotations

from typing import Any

from src.platform_core.governance.evidence_to_action import attach_governance_envelope
from src.platform_core.principles.report import build_principle_report_sections
from src.platform_core.principles.validator import validate_principles
from src.platform_core.proof.engine import run_proof_engine
from windows_network_toolkit.models import ProofAttempt, ProofResult
from windows_network_toolkit.proxy_classification import classify_from_live
from windows_network_toolkit.proxy_owner import detect_proxy_owner
from windows_network_toolkit.proxy_state import collect_proxy_state_model


def run_diagnose_proof(
    url: str | None = None,
    *,
    inject: dict[str, Any] | None = None,
    inject_proof: dict[str, Any] | None = None,
    **kwargs: Any,
) -> ProofResult:
    """Build a structured proof envelope for a proxy-state diagnosis.

    Collects live Windows evidence (or uses ``inject`` for deterministic tests),
    performs discrete proof attempts (port-listener check, WinINET/WinHTTP path
    comparison, optional URL probe), and assembles an ordered chain of
    Observation → Hypothesis → Proof → Conclusion.

    Args:
        url: Optional URL to probe via ``run_proof_engine``.  When provided,
            network connectivity tests are included as additional proof attempts
            and may raise the conclusion confidence ceiling to 0.9.
        inject: Optional pre-built proof dict for fixture-based testing.  Must
            contain ``proof_attempts`` (list of attempt dicts), ``hypothesis``
            (str), ``observation`` (dict), and ``conclusion`` (dict with
            ``status`` and ``confidence``).  When supplied, all live OS calls
            are skipped.
        inject_proof: Optional dict forwarded as the ``inject`` parameter to
            ``run_proof_engine`` when a ``url`` is also provided.  Allows
            deterministic network-probe simulation.
        **kwargs: Forwarded to ``collect_proxy_state_model``, ``detect_proxy_owner``,
            ``classify_from_live``, and ``run_proof_engine``.

    Returns:
        A ``ProofResult`` containing:

        - ``observation``: Snapshot of WinINET/WinHTTP fields and listener status.
        - ``hypothesis``: Human-readable candidate explanation for observed symptoms.
        - ``proof_attempts``: Ordered list of ``ProofAttempt`` (name, status, meaning).
        - ``conclusion_status``: ``"supported"``, ``"inconclusive"``, etc.
        - ``confidence``: Ordinal estimate in [0.0, 1.0]; not a probability of attack.
        - ``limitations``: Mandatory caveats — does not prove malware or MITM.

    Side effects:
        Live path: reads HKCU WinINET/WinHTTP registry keys and checks open TCP
        ports.  URL path: issues outbound HTTP(S) probes.  Inject path: none.

    Audit Notes:
        ``conclusion_status: "supported"`` does not confirm a security incident;
        it indicates the collected observations are consistent with the stated
        hypothesis.  Operators must not escalate to formal incident response on
        this result alone without corroborating evidence.
    """
    if inject:
        attempts = [
            ProofAttempt(**a) if isinstance(a, dict) else a
            for a in inject.get("proof_attempts", [])
        ]
        conclusion = inject.get("conclusion") or {}
        return ProofResult(
            observation=dict(inject.get("observation") or {}),
            hypothesis=str(inject.get("hypothesis") or ""),
            proof_attempts=attempts,
            conclusion_status=str(
                conclusion.get("status") or inject.get("conclusion_status") or ""
            ),
            confidence=float(conclusion.get("confidence") or inject.get("confidence") or 0.0),
            limitations=list(inject.get("limitations") or []),
        )

    state = collect_proxy_state_model(**kwargs)
    owner = detect_proxy_owner(**kwargs)
    classification = classify_from_live(**kwargs)

    listener_found = bool(owner.get("listener_found"))
    observation = {
        "wininet_proxy": state.wininet_proxy_server or "none",
        "wininet_enabled": state.wininet_proxy_enabled,
        "winhttp_direct": state.winhttp_direct_access,
        "localhost_port": state.localhost_port,
        "localhost_listener": listener_found,
    }

    attempts: list[ProofAttempt] = []

    if state.localhost_port is not None:
        status = "passed" if listener_found else "failed"
        meaning = (
            f"Process listening on port {state.localhost_port}."
            if listener_found
            else "No process is listening on the configured proxy port."
        )
        attempts.append(ProofAttempt("localhost_listener_check", status, meaning))

    if state.wininet_proxy_enabled and state.winhttp_direct_access:
        attempts.append(
            ProofAttempt(
                "wininet_winhttp_comparison",
                "supported",
                "Browser proxy path differs from WinHTTP direct path.",
            )
        )

    primary = classification.primary_classification
    if primary == "DEAD_PROXY_CONFIG":
        hypothesis = "Browser failure is likely caused by dead WinINET localhost proxy."
        conclusion_status = "supported"
        confidence = 0.92 if not listener_found else 0.5
    elif primary == "WININET_WINHTTP_MISMATCH":
        hypothesis = "Browser path may fail due to WinINET/WinHTTP configuration split."
        conclusion_status = "supported"
        confidence = 0.72
    elif primary == "NO_PROXY":
        hypothesis = "Proxy misconfiguration is unlikely the root cause."
        conclusion_status = "inconclusive"
        confidence = 0.3
    else:
        hypothesis = f"Proxy state classified as {primary}; further investigation needed."
        conclusion_status = "inconclusive"
        confidence = classification.confidence

    if url:
        proof = run_proof_engine(
            url,
            proxy_server=state.wininet_proxy_server or None,
            dead_localhost_proxy=primary == "DEAD_PROXY_CONFIG",
            inject=inject_proof,
            **kwargs,
        )
        for obs in proof.observations:
            attempts.append(
                ProofAttempt(
                    name=f"{obs.probe_type}",
                    status="passed" if obs.success else "failed",
                    meaning=obs.observed_value[:200],
                )
            )
        if proof.outcome.value == "DEAD_LOCALHOST_PROXY":
            conclusion_status = "supported"
            confidence = max(confidence, 0.9)

    limitations = [
        "This does not prove malware.",
        "This does not prove MITM.",
        "This supports whether the configured proxy path is broken or unavailable.",
    ]

    return ProofResult(
        observation=observation,
        hypothesis=hypothesis,
        proof_attempts=attempts,
        conclusion_status=conclusion_status,
        confidence=confidence,
        limitations=limitations,
    )


def enrich_diagnose_payload(payload: dict[str, Any], *, include_principles: bool) -> dict[str, Any]:
    """Optionally attach principle-compliance and governance envelope to a proof payload.

    When ``include_principles`` is ``False``, the payload is returned unchanged.
    When ``True``, the function validates the payload against platform principles,
    builds structured compliance sections, and wraps the result in the governance
    envelope (dry-run, requires confirmation).

    Args:
        payload: A serialised ``ProofResult`` dict (typically from
            ``ProofResult.to_dict()``).  Must contain ``conclusion`` (dict with
            ``status`` and ``confidence``) and ``limitations`` (list of str).
        include_principles: When ``True``, appends ``principle_compliance``,
            ``blocked_overclaims``, ``evidence_chain``, and
            ``safe_remediation_controls`` sections and attaches the governance
            envelope.

    Returns:
        The original ``payload`` dict unchanged (when ``include_principles`` is
        ``False``), or an enriched copy with governance sections and the
        ``governance_envelope`` wrapper (when ``True``).

    Side effects:
        None — the governance envelope is constructed in memory; no file writes.

    Audit Notes:
        The attached governance envelope sets ``dry_run=True`` and
        ``requires_confirmation=True`` unconditionally, regardless of the payload
        content.  Do not use this function's output as an authorisation record
        for live remediation.
    """
    if not include_principles:
        return payload

    validation_input = {
        "proof": payload,
        "classification": {
            "confidence": (payload.get("conclusion") or {}).get("confidence", 0.0),
            "limitations": payload.get("limitations") or [],
        },
        "remediation_requested": False,
    }
    compliance = validate_principles(validation_input)
    sections = build_principle_report_sections(
        compliance=compliance,
        proof=payload,
        limitations=payload.get("limitations"),
    )
    enriched = dict(payload)
    enriched.update(
        {
            "principle_compliance": sections["principle_compliance"],
            "blocked_overclaims": sections["blocked_overclaims"],
            "evidence_chain": sections["evidence_chain"],
            "safe_remediation_controls": sections["safe_remediation_controls"],
        }
    )
    conclusion = payload.get("conclusion") or {}
    return attach_governance_envelope(
        enriched,
        proof_conclusion=conclusion.get("status") if isinstance(conclusion, dict) else None,
        dry_run=True,
        requires_confirmation=True,
    )

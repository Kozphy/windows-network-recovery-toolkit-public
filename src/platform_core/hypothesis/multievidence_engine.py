"""Multievidence hypothesis engine — registry, process, timeline, network."""

from __future__ import annotations

import uuid
from typing import Any

from src.platform_core.hypothesis.models import (
    EvidenceKind,
    EvidenceRef,
    HypothesisEngineResult,
    HypothesisEvaluation,
    MultievidenceInput,
    RegistryEvidence,
)
from src.platform_core.hypothesis.scenarios import SCENARIOS, ScenarioTemplate
from src.platform_core.hypothesis.scorer import (
    compute_confidence,
    format_confidence_display,
    tier_is_proof,
)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "ok", "success", "enabled", "on"}
    return bool(value)


def _is_localhost_proxy(server: str | None) -> bool:
    if not server:
        return False
    s = server.lower()
    return "127.0.0.1" in s or "localhost" in s or "::1" in s


def build_signal_map(data: MultievidenceInput) -> dict[str, bool]:
    """Derive normalized boolean signals from four evidence domains."""
    signals: dict[str, bool] = {}

    reg = data.registry
    proc = data.process
    net = data.network
    tl = data.timeline

    if reg:
        signals["proxy_enabled"] = reg.proxy_enable == 1 if reg.proxy_enable is not None else False
        signals["localhost_proxy"] = _is_localhost_proxy(reg.proxy_server)
        signals["wininet_winhttp_mismatch"] = bool(
            reg.winhttp_direct is True and signals.get("proxy_enabled")
        )
        signals["registry_writer_confirmed"] = reg.writer_confirmed
        if reg.writer_confirmed and reg.writer_telemetry:
            signals["registry_writer_telemetry"] = True

    if proc:
        signals["listener_present"] = proc.listener_found
        signals["listener_absent"] = not proc.listener_found
        signals["known_dev_tool"] = proc.known_dev_tool
        signals["known_security_tool"] = proc.known_security_tool

    if net:
        if net.dns_ok is not None:
            signals["dns_ok"] = net.dns_ok
        if net.ping_ok is not None:
            signals["ping_ok"] = net.ping_ok
        if net.browser_https_ok is not None:
            signals["browser_https_fail"] = not net.browser_https_ok
        if net.direct_path_ok is not None:
            signals["direct_path_ok"] = net.direct_path_ok
            signals["proof_path_contrast"] = net.direct_path_ok and signals.get(
                "browser_https_fail", False
            )
        if net.proxied_path_ok is not None and net.proxied_path_ok is False:
            signals["proxy_bypass_succeeded"] = signals.get("browser_https_fail", False)
        if net.tls_cert_mismatch is not None:
            signals["tls_cert_mismatch"] = net.tls_cert_mismatch
            signals["tls_path_contrast"] = net.tls_cert_mismatch
        if net.vpn_active is not None:
            signals["vpn_active"] = net.vpn_active

    if tl:
        for ev in tl.events:
            key = ev.signal.lower()
            signals[key] = _truthy(ev.observed_value)
            if key == "browser_https_failed":
                signals["browser_https_fail"] = _truthy(ev.observed_value)
            if key == "direct_path_success":
                signals["direct_path_ok"] = _truthy(ev.observed_value)
                signals["proof_path_contrast"] = _truthy(ev.observed_value)
            if key == "listener_found" and _truthy(ev.observed_value) is False:
                signals["listener_absent"] = True

    if reg and proc and reg.writer_confirmed and proc.listener_found:
        signals["writer_and_listener_proof"] = True

    return signals


def collect_evidence_refs(data: MultievidenceInput) -> list[EvidenceRef]:
    """Collect evidence refs.

    Args:
        data: data supplied by the caller.

    Returns:
        The computed `list[EvidenceRef]` value.

    Side effects:
        Collects observations from the configured evidence source.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    refs: list[EvidenceRef] = []
    if data.registry:
        r = data.registry
        refs.append(
            EvidenceRef(
                evidence_id=r.evidence_id,
                kind=EvidenceKind.REGISTRY,
                signal="proxy_enable",
                tier=r.tier,
                observed_value=str(r.proxy_enable),
                summary=f"ProxyEnable={r.proxy_enable}, ProxyServer={r.proxy_server}",
                is_proof=tier_is_proof(r.tier),
            )
        )
        if r.winhttp_direct is not None:
            refs.append(
                EvidenceRef(
                    evidence_id=r.evidence_id,
                    kind=EvidenceKind.REGISTRY,
                    signal="winhttp_direct",
                    tier="OBSERVED_ONLY",
                    observed_value=str(r.winhttp_direct),
                    summary="WinHTTP direct access observation",
                )
            )
    if data.process:
        p = data.process
        refs.append(
            EvidenceRef(
                evidence_id=p.evidence_id,
                kind=EvidenceKind.PROCESS,
                signal="listener_found",
                tier=p.tier,
                observed_value=str(p.listener_found),
                summary=f"Listener on port {p.localhost_port}: {p.listener_found}",
                is_proof=tier_is_proof(p.tier),
            )
        )
    if data.network:
        n = data.network
        for sig, val in (
            ("dns_ok", n.dns_ok),
            ("browser_https_ok", n.browser_https_ok),
            ("direct_path_ok", n.direct_path_ok),
            ("tls_cert_mismatch", n.tls_cert_mismatch),
            ("vpn_active", n.vpn_active),
        ):
            if val is not None:
                refs.append(
                    EvidenceRef(
                        evidence_id=n.evidence_id,
                        kind=EvidenceKind.NETWORK,
                        signal=sig,
                        tier=n.tier,
                        observed_value=str(val),
                        summary=f"Network probe {sig}={val}",
                        is_proof=tier_is_proof(n.tier) and sig == "direct_path_ok",
                    )
                )
    if data.timeline:
        for idx, ev in enumerate(data.timeline.events[:8]):
            refs.append(
                EvidenceRef(
                    evidence_id=f"{data.timeline.evidence_id}-{idx}",
                    kind=EvidenceKind.TIMELINE,
                    signal=ev.signal,
                    tier="OBSERVED_ONLY",
                    observed_value=ev.observed_value,
                    summary=f"{ev.timestamp_utc}: {ev.signal}={ev.observed_value}",
                )
            )
    return refs


def _supporting_for_scenario(
    scenario: ScenarioTemplate,
    signals: dict[str, bool],
    all_refs: list[EvidenceRef],
) -> list[EvidenceRef]:
    wanted = (
        set(scenario.required_signals)
        | set(scenario.proof_signals)
        | set(scenario.supporting_signal_hints)
    )
    out: list[EvidenceRef] = []
    for ref in all_refs:
        sig_key = ref.signal.lower()
        if sig_key in wanted or any(s in sig_key for s in wanted):
            out.append(ref)
        elif (
            ref.signal == "listener_found"
            and "listener_absent" in wanted
            and ref.observed_value == "False"
        ):
            out.append(ref)
        elif ref.signal == "proxy_enable" and "proxy_enabled" in wanted:
            out.append(ref)
    if not out and signals.get("proxy_enabled"):
        out = [r for r in all_refs if r.kind == EvidenceKind.REGISTRY][:1]
    return out


def _missing_for_scenario(scenario: ScenarioTemplate, signals: dict[str, bool]) -> list[str]:
    missing: list[str] = []
    for req in scenario.required_signals:
        if not signals.get(req):
            missing.append(f"Required signal not observed: {req}")
    for m in scenario.missing_if_absent:
        if not signals.get(m):
            missing.append(f"Missing evidence for stronger claim: {m}")
    return missing


def _evaluate_scenario(
    scenario: ScenarioTemplate,
    signals: dict[str, bool],
    all_refs: list[EvidenceRef],
    *,
    cross_domain: bool,
) -> HypothesisEvaluation | None:
    if scenario.required_signals:
        matched = sum(1 for s in scenario.required_signals if signals.get(s))
        if matched == 0:
            return None
    else:
        matched = 0

    required_total = len(scenario.required_signals) or 1
    proof_matched = sum(1 for s in scenario.proof_signals if signals.get(s))
    missing = _missing_for_scenario(scenario, signals)
    supporting = _supporting_for_scenario(scenario, signals, all_refs)

    score, rank, explanation = compute_confidence(
        base_rank=scenario.base_rank,
        supporting=supporting,
        required_matched=matched,
        required_total=required_total,
        proof_matched=proof_matched,
        missing_count=len(missing),
        cross_domain_corroboration=cross_domain,
    )

    return HypothesisEvaluation(
        hypothesis_id=scenario.hypothesis_id,
        title=scenario.title,
        hypothesis=scenario.hypothesis,
        confidence=score,
        confidence_rank=rank,
        confidence_display=format_confidence_display(score),
        confidence_explanation=explanation,
        supporting_evidence=supporting,
        missing_evidence=missing,
        recommended_actions=list(scenario.recommended_actions),
        limitations=list(scenario.limitations),
        incident_type=scenario.incident_type,
    )


def evaluate_hypotheses(data: MultievidenceInput) -> HypothesisEngineResult:
    """Evaluate competing hypotheses from four evidence domains."""
    signals = build_signal_map(data)
    all_refs = collect_evidence_refs(data)
    cross_domain = bool(data.registry and (data.network or data.process))

    candidates: list[HypothesisEvaluation] = []
    for scenario in SCENARIOS:
        if scenario.hypothesis_id == "hyp-insufficient-data":
            continue
        ev = _evaluate_scenario(scenario, signals, all_refs, cross_domain=cross_domain)
        if ev:
            candidates.append(ev)

    candidates.sort(key=lambda h: h.confidence, reverse=True)

    if not candidates:
        fallback = _evaluate_scenario(
            next(s for s in SCENARIOS if s.hypothesis_id == "hyp-insufficient-data"),
            signals,
            all_refs,
            cross_domain=cross_domain,
        )
        assert fallback is not None
        candidates = [fallback]

    primary = candidates[0]
    alternatives = candidates[1:]
    if len(alternatives) < 2:
        insuf = next(s for s in SCENARIOS if s.hypothesis_id == "hyp-insufficient-data")
        alt_ev = _evaluate_scenario(insuf, signals, all_refs, cross_domain=cross_domain)
        if alt_ev and alt_ev.hypothesis_id != primary.hypothesis_id:
            alternatives.append(alt_ev)
        for alt in candidates[1:]:
            if alt.hypothesis_id != primary.hypothesis_id and alt not in alternatives:
                alternatives.append(alt)

    primary_alts = [a.title for a in alternatives[:4]]
    primary = primary.model_copy(
        update={
            "alternative_explanations": primary_alts
            or ["Insufficient competing scenarios matched."]
        }
    )
    for i, alt in enumerate(alternatives):
        other_titles = [primary.title] + [a.title for j, a in enumerate(alternatives) if j != i]
        alternatives[i] = alt.model_copy(update={"alternative_explanations": other_titles[:4]})

    return HypothesisEngineResult(
        incident_id=data.incident_id,
        primary=primary,
        alternatives=alternatives[:4],
        metadata={
            "signal_map": {k: v for k, v in signals.items() if v},
            "candidate_count": len(candidates),
        },
    )


def multievidence_from_fixture(
    payload: dict[str, Any], *, incident_id: str | None = None
) -> MultievidenceInput:
    """Build MultievidenceInput from CS1-style fixture JSON."""
    iid = incident_id or payload.get("case_id") or f"inc-{uuid.uuid4().hex[:12]}"
    state = payload.get("proxy_state") or {}
    owner = payload.get("proxy_owner") or {}
    classification = payload.get("classification") or {}

    registry = RegistryEvidence(
        evidence_id="ev-registry",
        tier="OBSERVED_ONLY",
        proxy_enable=1 if state.get("wininet_proxy_enabled") else 0,
        proxy_server=state.get("wininet_proxy_server"),
        winhttp_direct=state.get("winhttp_direct_access"),
    )
    writer = payload.get("writer_attribution") or {}
    if writer.get("registry_writer_confirmed"):
        registry = registry.model_copy(
            update={
                "writer_confirmed": True,
                "writer_process": (writer.get("snapshot") or {})
                .get("listener", {})
                .get("process_name"),
                "writer_telemetry": list(writer.get("telemetry_sources") or []),
                "tier": "PROVEN_REGISTRY_WRITER",
            }
        )

    from src.platform_core.hypothesis.models import (
        NetworkEvidence,
        ProcessEvidence,
        TimelineEvidence,
    )

    process = ProcessEvidence(
        evidence_id="ev-process",
        tier="CORRELATED" if owner.get("listener_found") else "OBSERVED_ONLY",
        listener_found=bool(owner.get("listener_found")),
        localhost_port=state.get("localhost_port") or owner.get("localhost_port"),
        pid=(owner.get("process") or {}).get("pid") if owner.get("process") else owner.get("pid"),
        process_name=(owner.get("process") or {}).get("name") if owner.get("process") else None,
    )

    network = NetworkEvidence(
        evidence_id="ev-network",
        tier="OBSERVED_ONLY",
        direct_path_ok=True
        if classification.get("primary_classification") == "DEAD_PROXY_CONFIG"
        else None,
        browser_https_ok=False
        if classification.get("primary_classification") == "DEAD_PROXY_CONFIG"
        else None,
    )

    timeline = None
    tl_path = payload.get("timeline_path")
    if tl_path:
        timeline = TimelineEvidence(evidence_id="ev-timeline")

    proof = payload.get("proof") or {}
    if proof.get("proof_attempts"):
        for attempt in proof["proof_attempts"]:
            if (
                attempt.get("name") == "wininet_winhttp_comparison"
                and attempt.get("status") == "supported"
            ):
                network = network.model_copy(
                    update={"tier": "PROVEN_NETWORK_IMPACT", "direct_path_ok": True}
                )

    return MultievidenceInput(
        incident_id=iid,
        registry=registry,
        process=process,
        network=network,
        timeline=timeline,
    )

"""Rank hypotheses for localhost proxy drift (inference only).

Module responsibility:
    Convert collected evidence into ranked ``Hypothesis`` rows and flat ``Observation`` lists
    using cautious language and shared limitation strings.

System placement:
    Called by ``workflow`` after collectors and validation complete.

Key invariants:
    * Primary hypothesis is ``hypotheses[0]`` when the list is non-empty.
    * Every hypothesis carries ``ATTRIBUTION_LISTENER_ONLY`` and ``MALWARE_FORBIDDEN`` limits.

Decision intent:
    Prefer dev-proxy operational stories when loopback listener + path assessment agree;
    escalate risk when proxy enabled but path is broken or HTTPS fails.

Audit Notes:
    * Hypothesis confidence is ordinal, not calibrated probability.
    * Competing ids are deprioritized scenarios, not falsified claims.
"""

from __future__ import annotations

from .constants import ATTRIBUTION_LISTENER_ONLY, MALWARE_FORBIDDEN
from .models import Hypothesis, Observation


def build_hypotheses(
    *,
    proxy: dict,
    listener: dict,
    dev: dict,
    validation: dict,
    path_assessment: dict | None,
    before: dict | None,
) -> tuple[list[Hypothesis], list[str], str]:
    """Rank investigation hypotheses from collected evidence.

    Args:
        proxy: Output of ``collect_proxy_state``.
        listener: Output of ``collect_listener_evidence``.
        dev: Output of ``collect_dev_process_correlation``.
        validation: Probe summary from ``run_validation``.
        path_assessment: Serialized path assessment or None.
        before: Optional LKG snapshot for drift context.

    Returns:
        Tuple of (ranked hypotheses, competing hypothesis ids, primary hypothesis id).

    Side effects:
        None.
    """
    lim = (ATTRIBUTION_LISTENER_ONLY, MALWARE_FORBIDDEN)
    enable = proxy.get("proxy_enable")
    server = str(proxy.get("proxy_server") or "")
    loopback = "127.0.0.1" in server or "localhost" in server.lower() or "::1" in server
    listen_block = listener.get("localhost_attribution") or {}
    listener_found = bool(listen_block.get("listener_found"))
    owners = listen_block.get("owners") or []
    dns_ok = validation.get("dns_ok")
    tcp_ok = validation.get("tcp_443_ok")
    https_ok = validation.get("https_ok")
    bypass_ok = validation.get("proxy_bypass_https_ok")
    proxied_ok = validation.get("proxied_https_ok")
    composite = (path_assessment or {}).get("composite_state")

    hyps: list[Hypothesis] = []

    if enable == 1 and loopback:
        if listener_found and composite == "LOOPBACK_OPERATIONAL":
            hyps.append(
                Hypothesis(
                    hypothesis_id="localhost_dev_proxy_operational",
                    title="Localhost developer proxy path appears operational",
                    confidence="high",
                    evidence_for=(
                        "proxy drift observed toward loopback",
                        "localhost listener correlated",
                        "HTTPS bypass/control probes succeeded",
                    ),
                    evidence_against=(),
                    limitations=lim,
                ),
            )
        elif listener_found and (composite == "LOOPBACK_BROKEN" or https_ok is False):
            hyps.append(
                Hypothesis(
                    hypothesis_id="localhost_proxy_stale_or_broken",
                    title="WinINET points at localhost proxy but path may be unhealthy",
                    confidence="high",
                    evidence_for=(
                        "proxy drift observed",
                        "listener present but browser-path may fail",
                    ),
                    evidence_against=(),
                    limitations=lim,
                ),
            )
        elif not listener_found:
            hyps.append(
                Hypothesis(
                    hypothesis_id="localhost_proxy_no_listener",
                    title="Loopback proxy configured without matching listener",
                    confidence="high",
                    evidence_for=("ProxyServer references loopback", "no listener on configured port"),
                    evidence_against=(),
                    limitations=lim,
                ),
            )

    if enable == 1 and bypass_ok is True and proxied_ok is False:
        hyps.append(
            Hypothesis(
                hypothesis_id="browser_proxy_path_regression",
                title="Browser-path likely affected by user proxy while bypass succeeds",
                confidence="high",
                evidence_for=("proxy bypass HTTPS succeeded", "proxied path failed or degraded"),
                evidence_against=(),
                limitations=lim,
            ),
        )

    if before and before.get("proxy_enable") == 0 and enable == 1:
        hyps.append(
            Hypothesis(
                hypothesis_id="wininet_proxy_drift_observed",
                title="WinINET proxy drift observed (OFF→ON or server change)",
                confidence="high",
                evidence_for=("before/after snapshot shows proxy enable or server change",),
                evidence_against=(),
                limitations=lim + ("Drift timing does not identify writer process.",),
            ),
        )

    dev_names = [str(o.get("process_name") or "").lower() for o in owners if isinstance(o, dict)]
    if any("node" in n for n in dev_names) or dev.get("dev_process_rows"):
        hyps.append(
            Hypothesis(
                hypothesis_id="node_electron_dev_tool_association",
                title="Node/Electron/developer tooling associated with listener (correlation only)",
                confidence="medium",
                evidence_for=("process association detected on proxy port or inventory",),
                evidence_against=("association is not registry-writer proof",),
                limitations=lim,
            ),
        )

    if dns_ok is False:
        hyps.append(
            Hypothesis(
                hypothesis_id="dns_path_issue",
                title="DNS resolution failure may explain connectivity symptoms",
                confidence="medium",
                evidence_for=("DNS probe failed",),
                evidence_against=(),
                limitations=(),
            ),
        )

    # Competing low-priority
    competing = ["upstream_outage", "unrelated_browser_extension"]
    if dns_ok and tcp_ok and https_ok:
        competing.append("upstream_outage — deprioritized because transport probes succeeded")

    if not hyps:
        hyps.append(
            Hypothesis(
                hypothesis_id="insufficient_proxy_drift_signal",
                title="Insufficient proxy drift signal in current sample",
                confidence="low",
                evidence_for=(),
                evidence_against=(),
                limitations=lim,
            ),
        )

    order = {"high": 0, "medium": 1, "low": 2}
    hyps.sort(key=lambda h: order.get(h.confidence, 3))
    primary = hyps[0].hypothesis_id
    return hyps, competing, primary


def observations_from_evidence(
    *,
    proxy: dict,
    listener: dict,
    dev: dict,
    validation: dict,
    before: dict | None,
) -> list[Observation]:
    """Flatten collector outputs into labeled observation rows.

    Args:
        proxy: Registry/snapshot dict from ``collect_proxy_state``.
        listener: Listener attribution dict.
        dev: Dev-process correlation dict.
        validation: Probe summary dict.
        before: Optional LKG snapshot for drift observations.

    Returns:
        List of ``Observation`` instances for reports and JSONL audit.
    """
    obs: list[Observation] = []
    obs.append(
        Observation(
            id="obs_wininet",
            category="registry",
            summary=f"WinINET ProxyEnable={proxy.get('proxy_enable')}, ProxyServer={proxy.get('proxy_server')!r}",
            detail={"proxy": proxy},
        ),
    )
    obs.append(
        Observation(
            id="obs_winhttp",
            category="registry",
            summary="WinHTTP proxy configuration captured",
            detail={"winhttp": proxy.get("winhttp")},
        ),
    )
    lb = listener.get("localhost_attribution") or {}
    obs.append(
        Observation(
            id="obs_listener",
            category="listener",
            summary=f"localhost listener_found={lb.get('listener_found')}, port={lb.get('localhost_port')}",
            detail=lb,
        ),
    )
    obs.append(
        Observation(
            id="obs_dev_processes",
            category="process",
            summary=f"Developer-related process rows: {len(dev.get('dev_process_rows') or [])}",
            detail=dev,
        ),
    )
    obs.append(
        Observation(
            id="obs_validation",
            category="probe",
            summary=(
                f"DNS={validation.get('dns_ok')}, TCP443={validation.get('tcp_443_ok')}, "
                f"HTTPS={validation.get('https_ok')}, bypass={validation.get('proxy_bypass_https_ok')}"
            ),
            detail=validation,
        ),
    )
    if before:
        obs.append(
            Observation(
                id="obs_before_snapshot",
                category="baseline",
                summary="Prior snapshot available for drift comparison",
                detail={"before": before},
            ),
        )
    return obs

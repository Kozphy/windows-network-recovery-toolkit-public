"""Hypothesis scenario templates — required and proof signals per scenario."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScenarioTemplate:
    """Represent the scenario template type.

    Key fields:
        hypothesis_id: Structured value carried by this type.
        incident_type: Structured value carried by this type.
        title: Structured value carried by this type.
        hypothesis: Structured value carried by this type.
        required_signals: Structured value carried by this type.
        proof_signals: Structured value carried by this type.
        supporting_signal_hints: Structured value carried by this type.
        missing_if_absent: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """

    hypothesis_id: str
    incident_type: str
    title: str
    hypothesis: str
    required_signals: tuple[str, ...]
    proof_signals: tuple[str, ...] = ()
    supporting_signal_hints: tuple[str, ...] = ()
    missing_if_absent: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    base_rank: str = "medium"


SCENARIOS: tuple[ScenarioTemplate, ...] = (
    ScenarioTemplate(
        hypothesis_id="hyp-dead-wininet-proxy",
        incident_type="DEAD_PROXY_CONFIG",
        title="Dead WinINET localhost proxy",
        hypothesis=(
            "Browser failure is likely caused by WinINET proxy pointing at a localhost port "
            "with no active listener."
        ),
        required_signals=("proxy_enabled", "localhost_proxy", "listener_absent"),
        proof_signals=("direct_path_ok", "browser_https_fail"),
        supporting_signal_hints=(
            "wininet_winhttp_mismatch",
            "proxy_bypass_succeeded",
        ),
        missing_if_absent=("proof_path_contrast", "registry_writer_telemetry"),
        limitations=(
            "Does not prove malware or MITM.",
            "Registry observation does not identify who wrote ProxyEnable.",
        ),
        recommended_actions=(
            "Run structured proof (diagnose --proof)",
            "Preview DISABLE_WININET_PROXY with typed confirmation",
            "Monitor with proxy-watch for reverter respawn",
        ),
        base_rank="high",
    ),
    ScenarioTemplate(
        hypothesis_id="hyp-unknown-local-listener",
        incident_type="UNKNOWN_LOCAL_PROXY",
        title="Unknown localhost proxy listener",
        hypothesis=(
            "An unclassified process is listening on the configured localhost proxy port; "
            "investigation required before remediation."
        ),
        required_signals=("proxy_enabled", "localhost_proxy", "listener_present"),
        proof_signals=(),
        missing_if_absent=("registry_writer_telemetry", "process_signature_verification"),
        limitations=(
            "Listener correlation is not registry-writer proof.",
            "Unknown process name does not imply malicious intent.",
        ),
        recommended_actions=(
            "Collect Sysmon E13 or Procmon registry writer evidence",
            "Inventory process hash and publisher",
            "Human review — do not auto-kill process",
        ),
        base_rank="low",
    ),
    ScenarioTemplate(
        hypothesis_id="hyp-dns-ok-browser-fail",
        incident_type="DNS_OK_BROWSER_FAIL",
        title="Application-path failure with healthy DNS",
        hypothesis=(
            "DNS and ICMP may succeed while browser/WinINET path fails due to proxy or TLS path issues."
        ),
        required_signals=("dns_ok", "browser_https_fail"),
        proof_signals=("direct_path_ok",),
        missing_if_absent=("tls_path_contrast",),
        limitations=("Network-layer success does not rule out proxy or TLS path failures.",),
        recommended_actions=("Run proxy-path and tls-proof contrast checks",),
        base_rank="medium",
    ),
    ScenarioTemplate(
        hypothesis_id="hyp-tls-mitm-indicators",
        incident_type="POSSIBLE_MITM_RISK",
        title="TLS path anomaly with proxy enabled",
        hypothesis=(
            "TLS certificate or path contrast suggests possible interception; requires further validation."
        ),
        required_signals=("tls_cert_mismatch", "proxy_enabled"),
        proof_signals=("tls_path_contrast",),
        missing_if_absent=("writer_and_listener_proof",),
        limitations=(
            "TLS mismatch alone does not prove malicious MITM.",
            "Requires independent certificate and path validation.",
        ),
        recommended_actions=(
            "Run tls-proof direct vs proxied contrast",
            "Escalate to security review",
        ),
        base_rank="medium",
    ),
    ScenarioTemplate(
        hypothesis_id="hyp-vpn-route-conflict",
        incident_type="VPN_ROUTE_CONFLICT",
        title="VPN split-tunnel or route conflict",
        hypothesis=(
            "Active VPN or split-tunnel configuration may conflict with WinINET proxy or browser path."
        ),
        required_signals=("vpn_active", "browser_https_fail"),
        missing_if_absent=("vpn_route_table", "proxy_state_under_vpn"),
        limitations=("VPN presence is observation — not proof of misconfiguration.",),
        recommended_actions=(
            "Review VPN split-tunnel policy",
            "Compare proxy state with VPN up/down",
        ),
        base_rank="low",
    ),
    ScenarioTemplate(
        hypothesis_id="hyp-benign-dev-proxy",
        incident_type="KNOWN_DEV_PROXY",
        title="Known development proxy tooling",
        hypothesis=(
            "Localhost proxy appears consistent with known development or debugging tooling."
        ),
        required_signals=("known_dev_tool", "listener_present"),
        limitations=("Dev tooling can still cause user-visible outages if misconfigured.",),
        recommended_actions=("OBSERVE_ONLY unless user impact confirmed",),
        base_rank="medium",
    ),
    ScenarioTemplate(
        hypothesis_id="hyp-insufficient-data",
        incident_type="ERROR_INSUFFICIENT_DATA",
        title="Insufficient evidence for strong hypothesis",
        hypothesis="Collected evidence is insufficient to prefer one root cause over alternatives.",
        required_signals=(),
        limitations=("Absence of evidence is not evidence of absence.",),
        recommended_actions=("Collect registry, process, network, and timeline evidence",),
        base_rank="low",
    ),
)

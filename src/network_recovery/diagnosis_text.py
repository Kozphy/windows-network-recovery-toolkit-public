"""Human-readable diagnosis for network recovery scenarios.

Module responsibility:
    Format operator-facing text from signals, events, and ranked hypotheses.

System placement:
    Used by ``engine.run_scenario_diagnosis`` for ``human_summary`` field.

Key invariants:
    * Does not claim malware or calibrated probabilities.
    * Surfaces epistemic boundary and limitations explicitly.

Side effects:
    None — returns str only.
"""

from __future__ import annotations

from .models import (
    DESKTOP_APP_PATH_DEGRADED_EVENT,
    RankedHypothesis,
    SignalBundle,
    VerificationStatus,
)


def format_diagnosis_report(
    *,
    signals: SignalBundle,
    events: list[str],
    hypotheses: list[RankedHypothesis],
    verification_status: VerificationStatus,
    primary_hypothesis_id: str,
    recovery_firewall_reset_helped: bool | None,
) -> str:
    """Build operator-facing text without overclaiming causality."""
    lines = [
        "NETWORK RECOVERY — APP PATH DIAGNOSIS",
        "=====================================",
        "",
        "Epistemic boundary: Observation ≠ Inference ≠ Proof",
        "",
        "SIGNALS (observation)",
        f"  Browser HTTPS (google):     {signals.browser_https_ok}",
        f"  ChatGPT/OpenAI HTTPS:       {signals.chatgpt_https_ok}",
        f"  Curl HTTPS (control):       {signals.curl_https_ok}",
        f"  DNS:                        {signals.dns_ok}",
        f"  WinINET ProxyEnable:        {signals.wininet_proxy_enable}",
        f"  WinINET ProxyServer:        {signals.wininet_proxy_server or '(empty)'}",
        f"  Localhost listeners:        {list(signals.localhost_listener_ports) or 'none'}",
        f"  ChatGPT process:            {signals.chatgpt_process_detected}",
        f"  Electron process:           {signals.electron_process_detected}",
        "",
        "EVENTS",
    ]
    if events:
        for ev in events:
            lines.append(f"  - {ev}")
    else:
        lines.append("  - (no canonical app-path degradation event emitted)")

    if DESKTOP_APP_PATH_DEGRADED_EVENT in events:
        lines.extend(
            [
                "",
                "Pattern: desktop app path degraded while browser path appears healthy.",
            ]
        )

    lines.extend(["", "HYPOTHESES (ordinal confidence — not probability)"])
    for h in hypotheses[:5]:
        lines.append(f"  - {h.hypothesis_id} [{h.confidence}]")
        for ev in h.evidence_for[:3]:
            lines.append(f"      + {ev}")
        for ev in h.evidence_against[:2]:
            lines.append(f"      - {ev}")

    lines.extend(["", f"Primary hypothesis: {primary_hypothesis_id}"])

    if verification_status == "supported_by_recovery_evidence":
        lines.extend(
            [
                "",
                "VERIFICATION",
                "Firewall/filtering interaction is supported by recovery evidence.",
                "(This is NOT proof of malicious activity.)",
            ]
        )
    elif verification_status == "contradicted_by_recovery_evidence":
        lines.append("\nVERIFICATION: Recovery evidence contradicts the primary firewall hypothesis.")
    else:
        lines.append("\nVERIFICATION: not_run (provide --recovery-feedback after a controlled test).")

    if recovery_firewall_reset_helped is True:
        lines.append("  Operator feedback: firewall reset helped restore the app.")

    lines.extend(
        [
            "",
            "LIMITATIONS",
            "  - Do not state malware, attack, or surveillance without explicit evidence tier.",
            "  - Listener/process correlation is not registry-writer proof.",
        ]
    )
    return "\n".join(lines)

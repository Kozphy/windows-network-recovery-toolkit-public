"""Classify bad-gateway root cause — diagnostic only.

Module responsibility:
    Map probe dict to cause_code, confidence, recommended_action, safety_notes.

System placement:
    Called by ``runner.run_bad_gateway_diagnose`` after ``collect_all``.

Key invariants:
    * Does not mutate system state.
    * ``SAFETY_NOTES`` always included in output.

Decision intent:
    Distinguish DNS/TCP failures, local proxy misconfig, loopback proxy, upstream 502.

Constraints:
    Confidence is heuristic float, not calibrated probability.
"""

from __future__ import annotations

from typing import Any

CauseCode = str  # LOCAL_PROXY_MISCONFIG | LOCAL_LOOPBACK_PROXY | ...

SAFETY_NOTES = [
    "Observation is not proof.",
    "Correlation is not causation.",
    "Confidence is not certainty.",
    "No host settings were modified during this diagnostic.",
]


def classify_cause(probes: dict[str, Any]) -> tuple[str, float, str, list[str]]:
    """Map collected probe results to a root-cause code and recommended action.

    Decision priority: DNS/TCP failure → local loopback proxy → local proxy
    misconfig → remote upstream failure → VPN/security proxy → inconclusive.

    Args:
        probes: Dict produced by ``collectors.collect_all`` with keys:
            ``dns``, ``tcp``, ``http_system_proxy``, ``http_direct``,
            ``wininet_proxy``, ``winhttp_proxy``, ``local_proxy_process``.

    Returns:
        A 4-tuple of:
            cause_code (str): One of ``LOCAL_PROXY_MISCONFIG``,
                ``LOCAL_LOOPBACK_PROXY``, ``VPN_SECURITY_PROXY``,
                ``DNS_TCP_CONNECTIVITY_ISSUE``, ``REMOTE_UPSTREAM_FAILURE``,
                or ``INCONCLUSIVE``.
            confidence (float): Ordinal heuristic in [0.0, 1.0].
            recommended_action (str): Operator action suggestion.
            safety_notes (list[str]): ``SAFETY_NOTES`` guardrails — always included.
    """
    dns = probes.get("dns") or {}
    tcp = probes.get("tcp") or {}
    http_sys = probes.get("http_system_proxy") or {}
    http_dir = probes.get("http_direct") or {}
    wininet = probes.get("wininet_proxy") or {}
    local = probes.get("local_proxy_process") or {}

    sys_status = http_sys.get("status_code")
    dir_status = http_dir.get("status_code")
    proxy_on = int(wininet.get("proxy_enable") or 0) == 1
    proxy_server = str(wininet.get("proxy_server") or "")
    loopback = "127.0.0.1" in proxy_server or "localhost" in proxy_server.lower()

    if not dns.get("ok"):
        return (
            "DNS_TCP_CONNECTIVITY_ISSUE",
            0.85,
            "INVESTIGATE_DNS_RESOLVER",
            SAFETY_NOTES,
        )
    if dns.get("ok") and not tcp.get("ok"):
        return (
            "DNS_TCP_CONNECTIVITY_ISSUE",
            0.80,
            "INVESTIGATE_TCP_PATH",
            SAFETY_NOTES,
        )

    if sys_status in {502, 504} and dir_status == 200:
        if loopback and local.get("detected"):
            return (
                "LOCAL_LOOPBACK_PROXY",
                0.82,
                "PREVIEW_PROXY_REMEDIATION_AFTER_CONFIRMATION",
                SAFETY_NOTES,
            )
        if proxy_on:
            return (
                "LOCAL_PROXY_MISCONFIG",
                0.78,
                "PREVIEW_PROXY_REMEDIATION_AFTER_CONFIRMATION",
                SAFETY_NOTES,
            )

    if sys_status in {502, 504} and dir_status in {502, 504}:
        return (
            "REMOTE_UPSTREAM_FAILURE",
            0.75,
            "ESCALATE_TO_UPSTREAM_OWNER",
            SAFETY_NOTES,
        )

    if proxy_on and ("zscaler" in proxy_server.lower() or "vpn" in proxy_server.lower()):
        return (
            "VPN_SECURITY_PROXY",
            0.65,
            "OBSERVE_ENTERPRISE_PROXY_POLICY",
            SAFETY_NOTES,
        )

    return ("INCONCLUSIVE", 0.50, "COLLECT_MORE_EVIDENCE", SAFETY_NOTES)


def headline(cause: str) -> str:
    """Return a short human-readable label for a cause code.

    Args:
        cause: A cause-code string from ``classify_cause``.

    Returns:
        A display-safe label string (e.g. ``"Likely local proxy problem"``).
        Returns ``"Inconclusive"`` for unrecognised codes.
    """
    mapping = {
        "LOCAL_PROXY_MISCONFIG": "Likely local proxy problem",
        "LOCAL_LOOPBACK_PROXY": "Likely local loopback proxy problem",
        "VPN_SECURITY_PROXY": "Likely VPN/security proxy path",
        "DNS_TCP_CONNECTIVITY_ISSUE": "Likely DNS or TCP/network problem",
        "REMOTE_UPSTREAM_FAILURE": "Likely remote upstream/server problem",
        "INCONCLUSIVE": "Inconclusive",
    }
    return mapping.get(cause, "Inconclusive")

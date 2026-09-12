"""Rolling-window reverter / flapping diagnosis for proxy-watch.

Module responsibility:
    Detect proxy enable/disable cycles, port churn, and repeated listener process names from
    proxy-watch change history — without claiming registry writer identity.

Decision intent:
    Flag ``REVERTER_SUSPECTED``, ``PROXY_FLAPPING``, or ``STALE_PROXY_AFTER_PROCESS_EXIT``
    patterns for human review and ``PROXY_REVERTER_DETECTION`` control tests.

Audit Notes:
    * ``suspected_reverter_process`` is correlation-only — escalate with Sysmon E13 if needed.
    * Empty event list returns status ``NONE`` with standard limitations.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ReverterDiagnosis:
    """Reverter/flapping diagnosis result from proxy-watch history.

    Attributes:
        status: Diagnosis outcome label: ``NONE``, ``REVERTER_SUSPECTED``,
            ``PROXY_FLAPPING``, ``REPEATED_LOCALHOST_PROXY_PORTS``,
            ``STALE_PROXY_AFTER_PROCESS_EXIT``, ``LOCAL_PROXY_ACTIVE``,
            ``DEAD_PROXY_CONFIG``, or a raw proxy_status string.
        transition_count: Total number of change events analysed.
        enable_disable_cycle_count: Number of off→on ProxyEnable flip cycles detected
            within the analysis window.
        last_ports: Up to five most recent localhost proxy port numbers observed.
        repeated_process_names: Process names that appeared in listener attribution
            two or more times across the event window (correlation only).
        repeated_command_line_hashes: SHA-256 prefix hashes of command-line strings
            seen two or more times (for reverter fingerprinting without PII storage).
        suspected_reverter_process: First repeated process name; ``None`` when no
            repetition detected. Attribution is correlation-only — not registry writer proof.
        confidence: Ordinal confidence in [0.0, 1.0]; not a calibrated probability.
        evidence: Human-readable evidence lines supporting the diagnosis.
        limitations: Mandatory epistemic caveats; always non-empty.
    """

    status: str = "NONE"
    transition_count: int = 0
    enable_disable_cycle_count: int = 0
    last_ports: list[int] = field(default_factory=list)
    repeated_process_names: list[str] = field(default_factory=list)
    repeated_command_line_hashes: list[str] = field(default_factory=list)
    suspected_reverter_process: str | None = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return asdict(self)


def _cmd_hash(cmdline: str | None) -> str | None:
    if not cmdline:
        return None
    return hashlib.sha256(cmdline.encode("utf-8", errors="replace")).hexdigest()[:16]


def analyze_proxy_watch_history(
    events: list[dict[str, Any]],
    *,
    window_seconds: float = 120.0,
) -> ReverterDiagnosis:
    """Detect flapping / reverter patterns from proxy-watch change events.

    Args:
        events: Change records with ``before``/``after`` state and optional ``owner``.
        window_seconds: Reserved window hint (currently uses full ``events`` list).

    Returns:
        ``ReverterDiagnosis`` with status, evidence lines, confidence, and limitations.

    Side effects:
        None.
    """
    limitations = [
        "Likely process / correlation only; registry writer proof unavailable.",
        "Flapping detection uses observed state transitions, not registry write events.",
    ]
    if not events:
        return ReverterDiagnosis(limitations=limitations)

    recent = list(events)
    diagnosis = ReverterDiagnosis(
        transition_count=len(recent),
        limitations=limitations,
    )

    enable_vals: list[int] = []
    ports: list[int] = []
    process_names: list[str] = []
    cmd_hashes: list[str] = []

    for i, ev in enumerate(recent):
        before = ev.get("before") or {}
        after = ev.get("after") or {}
        if i == 0 and before:
            enable_vals.append(int(before.get("wininet_proxy_enabled") or 0))
            port_b = before.get("localhost_port")
            if port_b is not None:
                try:
                    ports.append(int(port_b))
                except (TypeError, ValueError):
                    pass
        enable_vals.append(int(after.get("wininet_proxy_enabled") or 0))
        port = after.get("localhost_port")
        if port is not None:
            try:
                ports.append(int(port))
            except (TypeError, ValueError):
                pass
        owner = ev.get("owner") or {}
        proc = owner.get("process") if isinstance(owner.get("process"), dict) else {}
        name = proc.get("name")
        if name:
            process_names.append(str(name))
        h = _cmd_hash(proc.get("cmdline"))
        if h:
            cmd_hashes.append(h)

    diagnosis.last_ports = ports[-5:]

    cycles = 0
    for i in range(1, len(enable_vals)):
        if enable_vals[i - 1] == 1 and enable_vals[i] == 0:
            if i + 1 < len(enable_vals) and enable_vals[i + 1] == 1:
                cycles += 1
    diagnosis.enable_disable_cycle_count = cycles

    if process_names:
        from collections import Counter

        counts = Counter(process_names)
        repeated = [n for n, c in counts.items() if c >= 2]
        diagnosis.repeated_process_names = repeated
        if repeated:
            diagnosis.suspected_reverter_process = repeated[0]

    if cmd_hashes:
        from collections import Counter

        ch = Counter(cmd_hashes)
        diagnosis.repeated_command_line_hashes = [h for h, c in ch.items() if c >= 2]

    unique_ports = sorted(set(ports))
    evidence: list[str] = []

    same_port_reenable = False
    seen_disabled_ports: set[int] = set()
    seq_enable = enable_vals
    seq_ports = ports
    for i in range(1, len(seq_enable)):
        enabled_before = seq_enable[i - 1]
        enabled_after = seq_enable[i]
        port_ctx = seq_ports[i] if i < len(seq_ports) else (seq_ports[-1] if seq_ports else None)
        if enabled_before == 1 and enabled_after == 0 and port_ctx is not None:
            seen_disabled_ports.add(port_ctx)
        if enabled_before == 0 and enabled_after == 1 and port_ctx in seen_disabled_ports:
            same_port_reenable = True

    if cycles >= 1:
        diagnosis.status = "REVERTER_SUSPECTED"
        diagnosis.confidence = min(0.95, 0.6 + 0.15 * cycles)
        evidence.append(f"ProxyEnable cycled off→on {cycles} time(s) within watch window")
        if same_port_reenable:
            evidence.append("ProxyServer returned to same localhost port after manual disable")
    elif len(unique_ports) >= 2 and enable_vals and enable_vals[-1] == 1:
        diagnosis.status = "REPEATED_LOCALHOST_PROXY_PORTS"
        diagnosis.confidence = 0.7
        evidence.append(f"Localhost proxy ports changed across {unique_ports}")
    elif len(recent) >= 3 and len(set(enable_vals)) > 1:
        diagnosis.status = "PROXY_FLAPPING"
        diagnosis.confidence = 0.55
        evidence.append("Multiple proxy enable transitions in short window")

    if diagnosis.suspected_reverter_process:
        evidence.append(
            f"Repeated listener correlation: {diagnosis.suspected_reverter_process} "
            "(correlation only; not registry writer proof)"
        )

    stale = False
    for ev in reversed(recent):
        health = ev.get("health") or {}
        if health.get("proxy_status") == "DEAD_LOCALHOST_PROXY":
            stale = True
            break
        owner = ev.get("owner") or {}
        if (
            owner.get("listener_found") is False
            and int((ev.get("after") or {}).get("wininet_proxy_enabled") or 0) == 1
        ):
            stale = True
            break
    if stale and diagnosis.status == "NONE":
        diagnosis.status = "STALE_PROXY_AFTER_PROCESS_EXIT"
        diagnosis.confidence = 0.7
        evidence.append("Proxy enabled but listener absent — stale proxy config suspected")

    if diagnosis.status == "NONE" and enable_vals and enable_vals[-1] == 1:
        last_health = (recent[-1].get("health") or {}) if recent else {}
        ps = last_health.get("proxy_status")
        if ps in ("HEALTHY_LOCALHOST_PROXY", "BOTH_DIRECT_AND_PROXY_WORK", "PROXY_ONLY_WORKS"):
            diagnosis.status = "LOCAL_PROXY_ACTIVE"
            diagnosis.confidence = 0.6
        elif ps in ("DEAD_LOCALHOST_PROXY", "DIRECT_ONLY_WORKS"):
            diagnosis.status = "DEAD_PROXY_CONFIG"
            diagnosis.confidence = 0.85
        elif ps:
            diagnosis.status = str(ps)

    diagnosis.evidence = evidence
    return diagnosis

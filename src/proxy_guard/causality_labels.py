"""Explicit causality vocabulary for proxy attribution surfaces."""

from __future__ import annotations

# Evidence kinds (display / audit); not registry writer proof unless tier says so.
LISTENER_CORRELATION = "ListenerCorrelation"
REGISTRY_WRITER_PROOF = "RegistryWriterProof"
CPU_PROCESS_SNAPSHOT = "CpuProcessSnapshot"


def attribution_mode_label(mode: str | None) -> str:
    """Classify attribution ``mode`` for operator text."""

    m = (mode or "").lower()
    if m in {"verified_eventlog", "verified", "sysmon_confirmed"}:
        return REGISTRY_WRITER_PROOF
    if "listen" in m or m in {"best_effort_process_snapshot", "best_effort"}:
        return LISTENER_CORRELATION
    return "HeuristicAttribution"


def format_listener_correlation(
    *,
    process_name: str | None,
    pid: int | None,
    ppid: int | None = None,
    exe: str | None = None,
) -> list[str]:
    """Lines describing listen-port correlation only."""

    lines = [
        f"Evidence kind: {LISTENER_CORRELATION} (not {REGISTRY_WRITER_PROOF})",
        "A process was correlated with the configured localhost proxy port.",
        "This is candidate evidence only; it does not prove registry writer identity.",
    ]
    if process_name:
        lines.append(f"  Candidate process name (observed): {process_name}")
    if pid is not None:
        lines.append(f"  PID (observed): {pid}")
    if ppid is not None:
        lines.append(f"  Parent PID (observed): {ppid}")
    if exe:
        lines.append(f"  Executable path (observed): {exe}")
    return lines


def format_cpu_process_snapshot(process_names: list[str]) -> list[str]:
    """Lines for v1 ``recent_processes`` — never imply causality."""

    lines = [
        f"Evidence kind: {CPU_PROCESS_SNAPSHOT} (not {REGISTRY_WRITER_PROOF})",
        "Process names were CPU-active near the transition window.",
        "Correlation only — not proof any listed process changed WinINET keys.",
    ]
    for name in process_names:
        lines.append(f"  - {name} (correlated, not proven writer)")
    return lines


def process_candidate_wording(name: str) -> str:
    """Safe single-line reference to a process without implying causality."""

    return f"{name} (candidate / correlated — not proven registry writer)"

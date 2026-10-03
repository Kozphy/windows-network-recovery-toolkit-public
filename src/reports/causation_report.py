"""Pretty-text and JSON rendering for proxy causation results."""

from __future__ import annotations

import json
from typing import Any

from src.correlation.proxy_causation import ProxyCausationResult


def render_causation_text(
    result: ProxyCausationResult,
    *,
    transition_summary: str | None = None,
    observed_proxy_state: dict[str, Any] | None = None,
) -> str:
    """Render causation text.

    Args:
        result: The result value supplied by the caller.
        transition_summary: The transition summary value supplied by the caller.
        observed_proxy_state: The observed proxy state value supplied by the caller.

    Returns:
        The str result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    lines: list[str] = []
    if result.causation_level == "FINAL_CAUSATION":
        lines.append("=== Final causation found ===")
    else:
        lines.append(f"=== Causation analysis ({result.causation_level}) ===")

    lines.append("")
    lines.append(f"Classification: {result.classification}")
    lines.append(f"Confidence: {result.confidence:.2f}")
    lines.append(f"Explanation: {result.explanation}")

    if transition_summary:
        lines.append("")
        lines.append("Proxy transition:")
        lines.append(f"  {transition_summary}")

    if observed_proxy_state:
        lines.append("")
        lines.append("Observed proxy state:")
        for k, v in observed_proxy_state.items():
            lines.append(f"  {k}: {v}")

    lines.append("")
    lines.append("Registry writer:")
    if result.writer_process:
        lines.append(f"  Image: {result.writer_process}")
        lines.append(f"  PID: {result.writer_pid}")
        lines.append(f"  Command line: {result.writer_command_line or '(none)'}")
        lines.append(f"  Hashes: {result.writer_hashes or '(none)'}")
    else:
        lines.append("  (not established)")

    lines.append("")
    lines.append("Parent process:")
    lines.append(f"  {result.parent_process or '(unknown)'}")
    if result.parent_command_line:
        lines.append(f"  Command line: {result.parent_command_line}")

    if result.matched_registry_target:
        lines.append("")
        lines.append("Registry value changed:")
        lines.append(f"  Target: {result.matched_registry_target}")
        lines.append(f"  Details: {result.matched_registry_details}")

    if result.process_tree:
        lines.append("")
        lines.append("Process tree (Sysmon EID 1):")
        for node in result.process_tree:
            img = node.get("image") or node.get("process_guid") or "?"
            lines.append(f"  -> {img}")

    if result.network_events:
        lines.append("")
        lines.append("Network / listener evidence (Sysmon EID 3):")
        for ne in result.network_events[:5]:
            lines.append(
                f"  - {ne.get('Image')} port {ne.get('DestinationPort') or ne.get('SourcePort')}"
            )

    lines.append("")
    lines.append("Why this is causation vs correlation:")
    if result.causation_level == "FINAL_CAUSATION":
        lines.append(
            "  Sysmon Event ID 13 captured the exact registry SetValue on WinINET proxy keys "
            "within the time window, with Details matching the new proxy state."
        )
    elif result.causation_level == "STRONG_CAUSATION":
        lines.append(
            "  Registry write observed on the correct key, but Details did not fully match "
            "the expected value — treat as strong but not final proof."
        )
    else:
        lines.append(
            "  Only listener/process correlation or incomplete telemetry — "
            "this does NOT prove which process wrote HKCU proxy keys."
        )

    if result.limitations:
        lines.append("")
        lines.append("Remaining uncertainty:")
        for lim in result.limitations:
            lines.append(f"  - {lim}")

    return "\n".join(lines) + "\n"


def render_causation_json(
    result: ProxyCausationResult,
    *,
    extra: dict[str, Any] | None = None,
) -> str:
    """Render causation json.

    Args:
        result: The result value supplied by the caller.
        extra: The extra value supplied by the caller.

    Returns:
        The str result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    blob = result.to_dict()
    if extra:
        blob.update(extra)
    return json.dumps(blob, indent=2)

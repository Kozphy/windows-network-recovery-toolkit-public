"""Final causation engine — merge writer proof, port owner, path proof, and process tree.

Classifies root cause with explicit epistemic boundaries (observation vs proof).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .port_owner import PortOwnerEvidence, resolve_port_owner
from .process_tree import ProcessTreeEvidence, correlate_process_tree
from .proxy_path_proof import ProxyPathProof, collect_proxy_path_proof
from .registry_writer_proof import (
    RegistryWriteEvidence,
    best_registry_writer,
    collect_registry_writer_evidence,
)

FinalVerdict = Literal[
    "PROVEN_PROXY_WRITER_AND_PORT_OWNER",
    "PROVEN_PROXY_WRITER_ONLY",
    "LIKELY_LOCAL_PROXY_TOOL",
    "BENIGN_DEVELOPER_PROXY",
    "SUSPICIOUS_UNKNOWN_PROXY",
    "TOOL_CONFLICT_PROXY_FLAPPING",
    "INCONCLUSIVE",
]

ProofLevel = Literal[
    "OBSERVED_ONLY",
    "CORRELATED",
    "PROVEN_REGISTRY_WRITER",
    "PROVEN_NETWORK_IMPACT",
    "FINAL_CAUSATION",
]

_DEV_TOOL_NAMES = frozenset(
    {
        "node.exe",
        "nodejs.exe",
        "cursor.exe",
        "code.exe",
        "python.exe",
        "npm.cmd",
        "pnpm.exe",
        "yarn.exe",
    }
)


@dataclass
class FinalCausationReport:
    """Human and machine-readable final root-cause report."""

    verdict: FinalVerdict
    confidence: float
    proof_level: ProofLevel
    root_cause_sentence: str
    timeline: list[dict[str, Any]] = field(default_factory=list)
    evidence_tree: dict[str, Any] = field(default_factory=dict)
    recommended_next_action: list[str] = field(default_factory=list)
    safe_operator_commands: list[str] = field(default_factory=list)
    proven_vs_likely: dict[str, str] = field(default_factory=dict)
    current_proxy_state: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """To dict.
        
        Args:
            None.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "proof_level": self.proof_level,
            "root_cause_sentence": self.root_cause_sentence,
            "timeline": self.timeline,
            "evidence_tree": self.evidence_tree,
            "recommended_next_action": self.recommended_next_action,
            "safe_operator_commands": self.safe_operator_commands,
            "proven_vs_likely": self.proven_vs_likely,
            "current_proxy_state": self.current_proxy_state,
        }


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("/", "\\").split("\\")[-1].lower()


def _is_dev_tool(image: str, command_line: str) -> bool:
    base = _basename(image)
    if base in _DEV_TOOL_NAMES:
        return True
    low = command_line.lower()
    return any(name.replace(".exe", "") in low for name in _DEV_TOOL_NAMES)


def _is_suspicious_path(path: str) -> bool:
    low = path.lower()
    return any(x in low for x in ("\\appdata\\local\\temp\\", "\\temp\\", "\\appdata\\roaming\\"))


def _process_matches_port(writer_image: str, writer_pid: int | None, port_owner: PortOwnerEvidence | None) -> bool:
    if port_owner is None:
        return False
    if writer_pid is not None and port_owner.process_id == writer_pid:
        return True
    return _basename(writer_image) == _basename(port_owner.process_name) or _basename(writer_image) == _basename(
        port_owner.executable_path
    )


def _detect_flapping(transitions: list[dict[str, Any]]) -> bool:
    if len(transitions) < 2:
        return False
    enable_count = 0
    disable_count = 0
    for row in transitions:
        diff = row.get("diff") or {}
        before = diff.get("before") or {}
        after = diff.get("after") or {}
        if before.get("proxy_enable") == 0 and after.get("proxy_enable") == 1:
            enable_count += 1
        if before.get("proxy_enable") == 1 and after.get("proxy_enable") == 0:
            disable_count += 1
    return enable_count >= 1 and disable_count >= 1


def build_final_causation_report(
    *,
    proxy_change: dict[str, Any],
    registry_evidence: list[RegistryWriteEvidence],
    process_tree: ProcessTreeEvidence,
    port_owner: PortOwnerEvidence | None,
    path_proof: ProxyPathProof,
    recent_transitions: list[dict[str, Any]] | None = None,
) -> FinalCausationReport:
    """Classify final root cause from collected evidence layers."""
    writer = best_registry_writer(registry_evidence)
    diff = proxy_change.get("diff") or proxy_change
    after = diff.get("after") or proxy_change.get("after") or {}
    before = diff.get("before") or proxy_change.get("before") or {}

    timeline = [
        {"phase": "before", "state": before},
        {"phase": "after", "state": after},
    ]
    if writer:
        timeline.append(
            {
                "phase": "registry_write",
                "timestamp_utc": writer.timestamp_utc,
                "image": writer.image,
                "value": writer.written_value,
                "proof_level": writer.proof_level,
            }
        )

    proven_vs_likely: dict[str, str] = {
        "registry_writer": "not observed",
        "port_owner": "not observed",
        "network_path": "not tested",
    }
    if writer and writer.proof_level == "PROVEN":
        proven_vs_likely["registry_writer"] = f"proven — {writer.image} wrote {writer.registry_value_name}"
    elif writer:
        proven_vs_likely["registry_writer"] = f"likely/correlated only — {writer.image}"
    if port_owner:
        proven_vs_likely["port_owner"] = (
            f"correlated — {port_owner.process_name} listens on 127.0.0.1:{port_owner.port}"
        )
    if path_proof.proxied_path_ok is False:
        proven_vs_likely["network_path"] = "proven impact — proxied path fails"
    elif path_proof.proxied_path_ok is True:
        proven_vs_likely["network_path"] = "proxied path OK"

    proof_level: ProofLevel = "OBSERVED_ONLY"
    if writer and writer.proof_level == "PROVEN":
        proof_level = "PROVEN_REGISTRY_WRITER"
    elif port_owner or (writer and writer.proof_level == "CORRELATED"):
        proof_level = "CORRELATED"
    if path_proof.failure_mode == "proxy_broken":
        proof_level = "PROVEN_NETWORK_IMPACT"

    verdict: FinalVerdict = "INCONCLUSIVE"
    confidence = 0.35
    root_sentence = "Proxy settings changed; registry writer proof and port owner are unavailable."
    actions = [
        "Run: python -m src proxy-causation --since-minutes 30",
        "Enable Sysmon registry auditing (Event ID 13) for Internet Settings keys",
        "Collect Procmon RegSetValue export filtered to Internet Settings",
    ]
    safe_cmds = [
        "python -m src proxy-status",
        "python -m src proxy-owner",
        "python -m src proxy-causation --format markdown",
    ]

    suspicious_image = writer and _is_suspicious_path(writer.image)
    suspicious_port = port_owner and _is_suspicious_path(port_owner.executable_path)
    if suspicious_image or suspicious_port:
        verdict = "SUSPICIOUS_UNKNOWN_PROXY"
        confidence = 0.82 if writer and writer.proof_level == "PROVEN" else 0.78
        root_sentence = (
            f"Suspicious process context near proxy change: "
            f"{writer.image if writer else (port_owner.process_name if port_owner else 'unknown')}."
        )
        if writer and writer.proof_level == "PROVEN":
            proof_level = "FINAL_CAUSATION"
    elif recent_transitions and _detect_flapping(recent_transitions):
        verdict = "TOOL_CONFLICT_PROXY_FLAPPING"
        confidence = 0.72
        root_sentence = "Repeated enable/disable proxy flapping suggests conflicting tools (e.g. dev server vs IDE reset)."
        proof_level = "FINAL_CAUSATION" if writer and writer.proof_level == "PROVEN" else proof_level
    elif writer and writer.proof_level == "PROVEN":
        if port_owner and _process_matches_port(writer.image, writer.process_id, port_owner):
            verdict = "PROVEN_PROXY_WRITER_AND_PORT_OWNER"
            confidence = 0.92
            root_sentence = (
                f"{writer.image} provably wrote {writer.registry_value_name} and owns localhost port "
                f"{port_owner.port}."
            )
            proof_level = "FINAL_CAUSATION"
        else:
            verdict = "PROVEN_PROXY_WRITER_ONLY"
            confidence = 0.88
            root_sentence = f"{writer.image} provably wrote {writer.registry_value_name}; port owner not confirmed."
            proof_level = "FINAL_CAUSATION"
    elif port_owner and not writer:
        verdict = "LIKELY_LOCAL_PROXY_TOOL"
        confidence = 0.62
        root_sentence = (
            f"{port_owner.process_name} listens on 127.0.0.1:{port_owner.port} near proxy change "
            "(correlation — not registry write proof)."
        )
    elif writer or port_owner:
        image = (writer.image if writer else "") or (port_owner.process_name if port_owner else "")
        cmd = (writer.command_line if writer else "") or (port_owner.command_line if port_owner else "")
        if _is_dev_tool(image, cmd):
            verdict = "BENIGN_DEVELOPER_PROXY"
            confidence = 0.65
            root_sentence = f"Developer toolchain process near proxy change: {image}."

    if path_proof.failure_mode == "proxy_broken":
        actions.insert(0, "Verify localhost listener is running on configured proxy port")
        actions.insert(1, "Compare proxy-owner PID with attribution suspect — correlation ≠ writer proof")

    evidence_tree = {
        "registry_writes": [e.to_dict() for e in registry_evidence],
        "process_tree": process_tree.to_dict(),
        "port_owner": port_owner.to_dict() if port_owner else None,
        "path_proof": path_proof.to_dict(),
    }

    return FinalCausationReport(
        verdict=verdict,
        confidence=confidence,
        proof_level=proof_level,
        root_cause_sentence=root_sentence,
        timeline=timeline,
        evidence_tree=evidence_tree,
        recommended_next_action=actions,
        safe_operator_commands=safe_cmds,
        proven_vs_likely=proven_vs_likely,
        current_proxy_state=after,
    )


def collect_final_causation(
    *,
    repo_root: Path,
    proxy_change: dict[str, Any] | None = None,
    since_minutes: int = 30,
    fixture_dir: Path | None = None,
    run: Callable[..., Any] | None = None,
    recent_transitions: list[dict[str, Any]] | None = None,
) -> FinalCausationReport:
    """Collect all evidence layers and produce a final causation report."""
    from .state import snapshot_wininet_state

    scenario_data: dict[str, Any] = {}
    if fixture_dir and (fixture_dir / "scenario.json").is_file():
        import json

        scenario_data = json.loads((fixture_dir / "scenario.json").read_text(encoding="utf-8"))
        if proxy_change is None:
            proxy_change = scenario_data.get("proxy_change") or proxy_change
        if recent_transitions is None:
            recent_transitions = scenario_data.get("recent_transitions")

    sysmon_fixture = fixture_dir / "sysmon.json" if fixture_dir else None
    port_fixture = fixture_dir / "port_owner.json" if fixture_dir else None
    path_fixture = fixture_dir / "proxy_path.json" if fixture_dir else None
    tree_fixture = fixture_dir / "process_tree.json" if fixture_dir else None

    if proxy_change is None:
        state = snapshot_wininet_state(run=run) if run else snapshot_wininet_state()
        proxy_change = {"after": state, "before": {}, "diff": {"after": state, "before": {}}}

    diff = proxy_change.get("diff") or proxy_change
    after = diff.get("after") or {}
    port = None
    parsed = after.get("parsed_proxy_server") or {}
    if isinstance(parsed.get("localhost_port"), int):
        port = parsed["localhost_port"]
    elif isinstance(after.get("proxy_server"), str):
        m = re.search(r":(\d{1,5})$", after["proxy_server"])
        if m:
            port = int(m.group(1))

    from .registry_writer_proof import load_sysmon_events

    sysmon_path = sysmon_fixture if sysmon_fixture and sysmon_fixture.is_file() else None
    all_sysmon = load_sysmon_events(since_minutes=since_minutes, run=run, fixture_path=sysmon_path)
    registry_evidence = collect_registry_writer_evidence(
        since_minutes=since_minutes,
        run=run,
        fixture_path=sysmon_path,
        sysmon_events=all_sysmon if all_sysmon else None,
    )
    writer = best_registry_writer(registry_evidence)
    port_owner = resolve_port_owner(
        port,
        run=run or __import__("subprocess").run,
        fixture_path=port_fixture if port_fixture and port_fixture.is_file() else None,
    )
    path_proof = collect_proxy_path_proof(
        proxy_server=str(after.get("proxy_server") or ""),
        proxy_enabled=bool(after.get("proxy_enable")),
        run=run or __import__("subprocess").run,
        fixture_path=path_fixture if path_fixture and path_fixture.is_file() else None,
    )
    process_tree = correlate_process_tree(
        process_id=writer.process_id if writer else (port_owner.process_id if port_owner else None),
        process_guid=writer.process_guid if writer else None,
        sysmon_events=all_sysmon or None,
        fixture_path=tree_fixture if tree_fixture and tree_fixture.is_file() else None,
        run=run or __import__("subprocess").run,
    )
    return build_final_causation_report(
        proxy_change=proxy_change,
        registry_evidence=registry_evidence,
        process_tree=process_tree,
        port_owner=port_owner,
        path_proof=path_proof,
        recent_transitions=recent_transitions,
    )

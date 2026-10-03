"""Sysmon Event ID 13 registry-write attribution for WinINET proxy changes."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from src.telemetry.registry_targets import (
    details_matches_expected,
    is_proxy_registry_target,
    proxy_registry_value_name,
)
from src.telemetry.sysmon_reader import SysmonEvent, query_sysmon_events

from .process_tree import ProcessTreeBuilder

CausationLevel = Literal[
    "FINAL_CAUSATION",
    "STRONG_CAUSATION",
    "CORRELATION_ONLY",
    "UNKNOWN",
]

SafetyClassification = Literal[
    "KNOWN_DEV_PROXY",
    "KNOWN_SECURITY_TOOL",
    "UNKNOWN_LOCAL_PROXY",
    "SUSPICIOUS_PROXY",
    "POSSIBLE_MITM_RISK",
    "REGISTRY_WRITER_CONFIRMED",
]


@dataclass
class ProxyCausationResult:
    """Represent proxy causation result data used by the toolkit.

    Attributes:
        causation_level: Field or variant describing causation level evidence or state.
        classification: Field or variant describing classification evidence or state.
        writer_process: Field or variant describing writer process evidence or state.
        writer_command_line: Field or variant describing writer command line evidence or state.
        writer_hashes: Field or variant describing writer hashes evidence or state.
        writer_process_guid: Field or variant describing writer process guid evidence or state.
        writer_pid: Field or variant describing writer pid evidence or state.
        parent_process: Field or variant describing parent process evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    causation_level: CausationLevel
    classification: SafetyClassification
    writer_process: str | None = None
    writer_command_line: str | None = None
    writer_hashes: str | None = None
    writer_process_guid: str | None = None
    writer_pid: int | None = None
    parent_process: str | None = None
    parent_command_line: str | None = None
    process_tree: list[dict] = field(default_factory=list)
    registry_events: list[dict] = field(default_factory=list)
    network_events: list[dict] = field(default_factory=list)
    confidence: float = 0.0
    explanation: str = ""
    matched_registry_target: str | None = None
    matched_registry_details: str | None = None
    observed_localhost_port: int | None = None
    limitations: list[str] = field(default_factory=list)

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
            "causation_level": self.causation_level,
            "classification": self.classification,
            "writer_process": self.writer_process,
            "writer_command_line": self.writer_command_line,
            "writer_hashes": self.writer_hashes,
            "writer_process_guid": self.writer_process_guid,
            "writer_pid": self.writer_pid,
            "parent_process": self.parent_process,
            "parent_command_line": self.parent_command_line,
            "process_tree": self.process_tree,
            "registry_events": self.registry_events,
            "network_events": self.network_events,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "matched_registry_target": self.matched_registry_target,
            "matched_registry_details": self.matched_registry_details,
            "observed_localhost_port": self.observed_localhost_port,
            "limitations": self.limitations,
        }


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    except ValueError:
        return None


def _expected_values_from_diff(
    before_state: dict[str, Any],
    after_state: dict[str, Any],
    changed_fields: list[str] | None = None,
) -> dict[str, Any]:
    field_to_state = {
        "ProxyEnable": "proxy_enable",
        "proxy_enable": "proxy_enable",
        "ProxyServer": "proxy_server",
        "proxy_server": "proxy_server",
        "AutoConfigURL": "auto_config_url",
        "auto_config_url": "auto_config_url",
        "ProxyOverride": "proxy_override",
        "proxy_override": "proxy_override",
    }
    expected: dict[str, Any] = {}
    for f in changed_fields or []:
        st_key = field_to_state.get(f)
        if st_key:
            expected[st_key] = after_state.get(st_key)
    for st_key in ("proxy_enable", "proxy_server", "auto_config_url", "proxy_override"):
        if st_key not in expected and before_state.get(st_key) != after_state.get(st_key):
            expected[st_key] = after_state.get(st_key)
    return expected


def _load_allowlist(repo_root: Path | None) -> dict[str, set[str]]:
    trusted_proc: set[str] = set()
    trusted_paths: set[str] = set()
    if repo_root is None:
        return {"processes": trusted_proc, "paths": trusted_paths}
    path = repo_root / "config" / "proxy_allowlist.yaml"
    if not path.is_file():
        return {"processes": trusted_proc, "paths": trusted_paths}
    try:
        text = path.read_text(encoding="utf-8").lower()
    except OSError:
        return {"processes": trusted_proc, "paths": trusted_paths}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("- ") and "trusted_processes" in text[: text.find(line)]:
            trusted_proc.add(line[2:].strip())
        if ".exe" in line and "trusted_paths" in text:
            if line.startswith("- "):
                trusted_paths.add(line[2:].strip())
    # minimal yaml parse without dependency
    import re

    for m in re.finditer(r"trusted_processes:.*?(?=trusted_|\Z)", text, re.S):
        block = m.group(0)
        for proc in re.findall(r"-\s*(\S+\.exe)", block):
            trusted_proc.add(proc.lower())
    for m in re.finditer(r"trusted_paths:.*?(?=trusted_|\Z)", text, re.S):
        block = m.group(0)
        for p in re.findall(r"-\s*(.+)", block):
            trusted_paths.add(p.strip().lower())
    return {"processes": trusted_proc, "paths": trusted_paths}


def _classify_writer(
    image: str | None,
    *,
    allowlist: dict[str, set[str]],
    has_registry_proof: bool,
    is_localhost: bool,
) -> SafetyClassification:
    if not image:
        return "UNKNOWN_LOCAL_PROXY"
    base = image.split("\\")[-1].lower()
    path_low = image.lower()
    if has_registry_proof:
        if base in allowlist.get("processes", set()) or any(
            p in path_low for p in allowlist.get("paths", set())
        ):
            return "KNOWN_DEV_PROXY"
        if any(x in base for x in ("fiddler", "charles", "mitmproxy", "burp")):
            return "KNOWN_SECURITY_TOOL"
        if not is_localhost:
            return "POSSIBLE_MITM_RISK"
        return "REGISTRY_WRITER_CONFIRMED"
    if base in allowlist.get("processes", set()):
        return "KNOWN_DEV_PROXY"
    if is_localhost:
        return "UNKNOWN_LOCAL_PROXY"
    return "SUSPICIOUS_PROXY"


def _score_registry_match(
    ev: SysmonEvent,
    expected_by_value: dict[str, Any],
) -> tuple[float, bool]:
    """Return (score, details_match)."""
    if ev.event_id not in (12, 13, 14):
        return 0.0, False
    target = ev.target_object or ""
    if not is_proxy_registry_target(target):
        return 0.0, False
    vname = proxy_registry_value_name(target)
    if not vname:
        return 0.3, False
    # map to state keys
    state_key = {
        "proxyenable": "proxy_enable",
        "proxyserver": "proxy_server",
        "autoconfigurl": "auto_config_url",
        "proxyoverride": "proxy_override",
    }.get(vname, vname)
    expected = expected_by_value.get(state_key)
    details = ev.details or ""
    if expected is not None and details_matches_expected(vname, details, expected):
        return 1.0, True
    if details:
        return 0.75, False
    return 0.55, False


def analyze_proxy_causation(
    *,
    timestamp_utc: str,
    before_state: dict[str, Any],
    after_state: dict[str, Any],
    changed_fields: list[str] | None = None,
    observed_localhost_port: int | None = None,
    listener_process: dict[str, Any] | None = None,
    window_seconds: int = 10,
    sysmon_events: list[SysmonEvent] | None = None,
    run: Callable[..., Any] | None = None,
    repo_root: Path | None = None,
) -> ProxyCausationResult:
    """Correlate proxy-watch transition with Sysmon registry writes (read-only)."""
    limitations = [
        "Listener correlation does not prove registry authorship without Sysmon Event ID 13.",
        "Classification is neutral posture — not a malware verdict.",
    ]
    anchor = _parse_ts(timestamp_utc)
    if anchor is None:
        return ProxyCausationResult(
            causation_level="UNKNOWN",
            classification="UNKNOWN_LOCAL_PROXY",
            confidence=0.0,
            explanation="Invalid transition timestamp; cannot query Sysmon window.",
            limitations=limitations,
        )

    window = timedelta(seconds=max(1, window_seconds))
    if sysmon_events is None:
        events = query_sysmon_events(
            anchor - window,
            anchor + window,
            run=run,
        )
    else:
        events = sysmon_events

    expected = _expected_values_from_diff(before_state, after_state, changed_fields)
    registry_candidates: list[tuple[SysmonEvent, float, bool]] = []
    for ev in events:
        score, details_ok = _score_registry_match(ev, expected)
        if score > 0:
            registry_candidates.append((ev, score, details_ok))

    registry_candidates.sort(key=lambda x: x[1], reverse=True)
    tree_builder = ProcessTreeBuilder([e for e in events if e.event_id == 1])

    best: SysmonEvent | None = None
    best_details_match = False
    if registry_candidates:
        best, _, best_details_match = registry_candidates[0]

    network_hits: list[dict] = []
    if observed_localhost_port is not None:
        for ev in events:
            if ev.event_id != 3:
                continue
            if (
                ev.destination_port == observed_localhost_port
                or ev.source_port == observed_localhost_port
            ):
                network_hits.append(ev.to_dict())

    allowlist = _load_allowlist(repo_root)
    is_localhost = bool(
        observed_localhost_port or str(after_state.get("proxy_server") or "").startswith("127.")
    )

    writer_image = best.image if best else None
    writer_guid = best.process_guid if best else None
    writer_pid = best.process_id if best else None
    writer_cmd = best.command_line if best else None
    writer_hashes = best.hashes if best else None
    parent_image = best.parent_image if best else None
    parent_cmd = best.parent_command_line if best else None

    process_tree = tree_builder.ancestor_chain(writer_guid) if writer_guid else []

    if listener_process and not writer_image:
        writer_image = listener_process.get("name") or listener_process.get("process_name")
        writer_pid = listener_process.get("pid")
        parent_image = listener_process.get("parent_name")

    classification = _classify_writer(
        writer_image,
        allowlist=allowlist,
        has_registry_proof=best is not None,
        is_localhost=is_localhost,
    )

    registry_event_dicts = [c[0].to_dict() for c in registry_candidates[:5]]

    if best and best_details_match:
        level: CausationLevel = "FINAL_CAUSATION"
        confidence = 0.95
        explanation = (
            f"Sysmon Event ID {best.event_id} shows {best.image} wrote "
            f"{best.target_object} = {best.details} within ±{window_seconds}s of proxy change."
        )
    elif best:
        level = "STRONG_CAUSATION"
        confidence = 0.82
        explanation = (
            f"Sysmon registry event on {best.target_object} by {best.image}, "
            f"but Details did not exactly match expected new value."
        )
    elif listener_process or observed_localhost_port:
        level = "CORRELATION_ONLY"
        confidence = 0.45
        explanation = (
            "Likely process / correlation only; registry writer proof unavailable "
            "(no matching Sysmon Event ID 13 in window)."
        )
    else:
        level = "UNKNOWN"
        confidence = 0.1
        explanation = "No Sysmon registry writer and no localhost listener correlation in window."

    # NVIDIA python false attribution guard: python without registry proof stays low
    if writer_image and "python.exe" in writer_image.lower() and level == "CORRELATION_ONLY":
        listener_cmd = (listener_process or {}).get("command_line") if listener_process else None
        cmd_blob = f"{writer_cmd or ''} {listener_cmd or ''}".lower()
        if "nvidia" in cmd_blob:
            confidence = min(confidence, 0.25)
            explanation += " Python/NVIDIA context without registry write — LOW confidence."

    return ProxyCausationResult(
        causation_level=level,
        classification=classification,
        writer_process=writer_image,
        writer_command_line=writer_cmd,
        writer_hashes=writer_hashes,
        writer_process_guid=writer_guid,
        writer_pid=writer_pid,
        parent_process=parent_image,
        parent_command_line=parent_cmd,
        process_tree=process_tree,
        registry_events=registry_event_dicts,
        network_events=network_hits,
        confidence=confidence,
        explanation=explanation,
        matched_registry_target=best.target_object if best else None,
        matched_registry_details=best.details if best else None,
        observed_localhost_port=observed_localhost_port,
        limitations=limitations,
    )


def analyze_from_proxy_watch_row(
    row: dict[str, Any],
    *,
    window_seconds: int = 10,
    sysmon_events: list[SysmonEvent] | None = None,
    run: Callable[..., Any] | None = None,
    repo_root: Path | None = None,
) -> ProxyCausationResult:
    """Run causation analysis for one ``proxy_change_detected`` JSONL row."""
    diff = row.get("diff") or {}
    before = diff.get("before") or {}
    after = diff.get("after") or {}
    changed = diff.get("changed_fields") or []
    ts = str(row.get("timestamp") or "")
    port: int | None = None
    parsed = after.get("parsed_proxy_server") or {}
    if isinstance(parsed, dict) and isinstance(parsed.get("localhost_port"), int):
        port = parsed["localhost_port"]
    elif isinstance(after.get("proxy_server"), str) and ":" in after["proxy_server"]:
        try:
            port = int(after["proxy_server"].rsplit(":", 1)[-1])
        except ValueError:
            port = None
    suspect = (row.get("attribution") or {}).get("primary_suspect") or {}
    listener = suspect if isinstance(suspect, dict) else None
    return analyze_proxy_causation(
        timestamp_utc=ts,
        before_state=before,
        after_state=after,
        changed_fields=list(changed) if isinstance(changed, list) else None,
        observed_localhost_port=port,
        listener_process=listener,
        window_seconds=window_seconds,
        sysmon_events=sysmon_events,
        run=run,
        repo_root=repo_root,
    )

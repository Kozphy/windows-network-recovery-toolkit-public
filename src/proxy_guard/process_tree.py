"""Process tree rendering and Sysmon-backed lineage correlation.

Includes:
    - Parent-pointer chains for investigation reports (``build_process_chain_nodes``).
    - :class:`ProcessTreeEvidence` from Sysmon Event ID 1 or live WMI/CIM snapshots.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.correlation.process_tree import ProcessTreeBuilder
from src.telemetry.sysmon_reader import SysmonEvent


@dataclass
class ProcessTreeEvidence:
    """Reconstructed lineage for a focus process."""

    process: dict[str, Any]
    parent: dict[str, Any] | None
    grandparent: dict[str, Any] | None
    chain: list[dict[str, Any]] = field(default_factory=list)
    source: str = "unknown"
    confidence: float = 0.5

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
            "process": self.process,
            "parent": self.parent,
            "grandparent": self.grandparent,
            "chain": self.chain,
            "source": self.source,
            "confidence": self.confidence,
        }


def correlate_process_tree(
    *,
    process_id: int | None = None,
    process_guid: str | None = None,
    timestamp_utc: str | None = None,
    sysmon_events: list[SysmonEvent] | None = None,
    process_rows: list[dict[str, Any]] | None = None,
    fixture_path: Path | None = None,
    run: Callable[..., Any] = subprocess.run,
) -> ProcessTreeEvidence:
    """Reconstruct process → parent → grandparent lineage.

    Prefers Sysmon Event ID 1 graph when ``process_guid`` or matching PID is available;
    falls back to enriched process inventory rows or fixture JSON.
    """
    if fixture_path is not None and fixture_path.is_file():
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
        tree = data.get("process_tree") if isinstance(data, dict) else data
        if isinstance(tree, dict):
            chain = list(tree.get("chain") or [])
            return ProcessTreeEvidence(
                process=dict(tree.get("process") or (chain[-1] if chain else {})),
                parent=tree.get("parent"),
                grandparent=tree.get("grandparent"),
                chain=chain,
                source="fixture",
                confidence=float(tree.get("confidence") or 0.8),
            )

    if sysmon_events and (process_guid or process_id):
        builder = ProcessTreeBuilder(sysmon_events)
        focus_guid = process_guid
        if not focus_guid and process_id is not None:
            for ev in sysmon_events:
                if ev.event_id == 1 and ev.process_id == process_id and ev.process_guid:
                    focus_guid = ev.process_guid
                    break
        chain = _enrich_chain_from_sysmon(builder.ancestor_chain(focus_guid), sysmon_events)
        if chain:
            proc = chain[-1]
            parent = chain[-2] if len(chain) >= 2 else None
            grand = chain[-3] if len(chain) >= 3 else None
            return ProcessTreeEvidence(
                process=proc,
                parent=parent,
                grandparent=grand,
                chain=chain,
                source="sysmon_eid1",
                confidence=0.85,
            )

    if process_rows and process_id is not None:
        nodes = build_process_chain_nodes(
            focus_pid=process_id, process_rows=process_rows, matched_port=None
        )
        if nodes:
            proc = nodes[-1]
            parent = nodes[-2] if len(nodes) >= 2 else None
            grand = nodes[-3] if len(nodes) >= 3 else None
            return ProcessTreeEvidence(
                process=proc,
                parent=parent,
                grandparent=grand,
                chain=nodes,
                source="process_inventory",
                confidence=0.6,
            )

    _ = timestamp_utc, run
    return ProcessTreeEvidence(
        process={},
        parent=None,
        grandparent=None,
        chain=[],
        source="unavailable",
        confidence=0.0,
    )


def _enrich_chain_from_sysmon(
    chain: list[dict[str, Any]], events: list[SysmonEvent]
) -> list[dict[str, Any]]:
    """Attach user, hashes, and start time from matching Sysmon E1 rows."""
    by_guid = {
        (ev.process_guid or "").lower(): ev for ev in events if ev.event_id == 1 and ev.process_guid
    }
    enriched: list[dict[str, Any]] = []
    for node in chain:
        row = dict(node)
        guid = str(row.get("process_guid") or "").lower()
        ev = by_guid.get(guid)
        if ev:
            row.setdefault("user", ev.user)
            row.setdefault("start_time_utc", ev.utc_time)
            row.setdefault("hashes", ev.hashes)
            row.setdefault("executable_path", row.get("image"))
            row.setdefault("signed", None)
        enriched.append(row)
    return enriched


def build_process_chain_nodes(
    *,
    focus_pid: int | None,
    process_rows: list[dict[str, Any]],
    matched_port: int | None,
) -> list[dict[str, Any]]:
    """Walk parent pointers from focus PID upward; attach listen annotation on focus."""
    if focus_pid is None:
        return []
    by_pid = {int(r["pid"]): r for r in process_rows if isinstance(r.get("pid"), int)}
    chain: list[dict[str, Any]] = []
    seen: set[int] = set()
    pid: int | None = focus_pid
    while pid is not None and pid not in seen and pid > 4:
        seen.add(pid)
        row = by_pid.get(pid) or {}
        chain.append(
            {
                "pid": pid,
                "process_name": row.get("process_name") or row.get("parent_process_name"),
                "executable_path": row.get("executable_path"),
                "command_line": row.get("command_line"),
                "parent_pid": row.get("parent_pid"),
                "listens_on_localhost_port": matched_port if pid == focus_pid else None,
            }
        )
        ppid = row.get("parent_pid")
        pid = int(ppid) if isinstance(ppid, int) else None
    return list(reversed(chain))


def render_process_tree_text(
    nodes: list[dict[str, Any]],
    *,
    matched_port: int | None = None,
) -> str:
    """Human-readable tree, e.g. Cursor.exe -> powershell.exe -> node.exe (listens on PORT)."""
    if not nodes:
        return "(no process tree resolved)"
    lines: list[str] = []
    depth = 0
    for node in nodes:
        name = str(node.get("process_name") or "unknown")
        prefix = "  " * depth + ("└─ " if depth else "")
        port = node.get("listens_on_localhost_port") or (
            matched_port if depth == len(nodes) - 1 else None
        )
        if port:
            lines.append(f"{prefix}{name}\n{'  ' * (depth + 1)}└─ listens on 127.0.0.1:{port}")
        else:
            lines.append(f"{prefix}{name}")
        depth += 1
    return "\n".join(lines)


def render_process_tree_json(
    nodes: list[dict[str, Any]],
    *,
    matched_port: int | None = None,
) -> dict[str, Any]:
    """Structured nested tree for JSON reports."""
    if not nodes:
        return {"root": None, "matched_localhost_port": matched_port}
    root: dict[str, Any] | None = None
    current: dict[str, Any] | None = None
    for node in nodes:
        item = {
            "pid": node.get("pid"),
            "process_name": node.get("process_name"),
            "executable_path": node.get("executable_path"),
            "command_line": node.get("command_line"),
            "listens_on_localhost_port": node.get("listens_on_localhost_port")
            or (matched_port if node is nodes[-1] else None),
            "children": [],
        }
        if root is None:
            root = item
            current = item
        elif current is not None:
            current["children"].append(item)
            current = item
    return {"root": root, "matched_localhost_port": matched_port, "flat_chain": nodes}

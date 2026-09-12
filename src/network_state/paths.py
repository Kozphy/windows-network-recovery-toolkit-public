"""Filesystem contract for Network State Manager artifacts.

Keeps literals centralized so CLI handlers and tests agree on sinks without importing argparse.
All resolved paths nest under the toolkit checkout (or ``--repo-root`` surrogate) —
nothing here reads environment variables besides normal path resolution.

Key invariants:
    * Locations are relative to ``repo_root``; callers normalize ``repo_root.resolve()`` first.
    * Files may not exist until first write; callers must ``mkdir`` parents per writer module.

Side effects:
    None — pure path construction.

Raises:
    None.

Audit Notes:
    Append-only sinks live under ``logs/`` while ``reports/`` holds regenerated summaries.

See Also:
    :mod:`snapshot_store`, :mod:`events`, :mod:`audit`.
"""

from __future__ import annotations

from pathlib import Path


def snapshots_jsonl(repo_root: Path) -> Path:
    """Append-only named snapshots for Network State tooling."""
    return repo_root / "logs" / "network_state_snapshots.jsonl"


def default_profile_json(repo_root: Path) -> Path:
    """Single-file default profile replicated from JSONL selections."""
    return repo_root / "config" / "network_state_default.json"


def policy_json(repo_root: Path) -> Path:
    """Optional allow/block policy overlay (missing file ⇒ defaults in Python)."""
    return repo_root / "config" / "network_state_policy.json"


def events_jsonl(repo_root: Path) -> Path:
    """Operator event stream destined for UX/tray ingestion."""
    return repo_root / "logs" / "network_state_events.jsonl"


def audit_jsonl(repo_root: Path) -> Path:
    """Structured restore-phase audit complementary to Proxy Guard sinks."""
    return repo_root / "logs" / "network_state_audit.jsonl"


def evidence_jsonl(repo_root: Path) -> Path:
    """Optional imported Procmon/Sysmon-style rows after CSV normalization."""
    return repo_root / "logs" / "network_state_evidence.jsonl"


def report_txt(repo_root: Path) -> Path:
    """Human-readable rollup mirroring CLI ``network-state report``."""
    return repo_root / "reports" / "network_state_report.txt"


def report_json(repo_root: Path) -> Path:
    """Machine-readable twin of ``report_txt``."""
    return repo_root / "reports" / "network_state_report.json"

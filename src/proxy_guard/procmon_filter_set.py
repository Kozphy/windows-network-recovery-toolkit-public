"""Canonical Process Monitor filter set for WinINET proxy registry writes.

Module responsibility:
    Ship a deterministic, machine-readable Procmon filter recipe targeting
    ``RegSetValue`` on HKCU Internet Settings proxy keys, plus human operator
    instructions for Filter → Add and CSV export.

System placement:
    Used by ``python -m src procmon-filter-set`` and docs under
    ``docs/procmon_proxy_filter.md``. CSV exports feed
    :mod:`~src.proxy_guard.procmon_import` and ``proxy-attribution --procmon``.

Key invariants:
    * This module never launches Procmon or mutates the host.
    * Filter rules are Include-oriented; operators must drop non-matching events
      in Procmon (Filter → Drop Filtered Events).
    * Observation of a matching row is still subject to Procmon capture gaps;
      it raises evidence toward writer proof, not absolute certainty.

Audit Notes:
    Preserve original Procmon PML/CSV beside toolkit JSONL when custody matters.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FILTER_SET_ID = "wininet_proxy_regsetvalue_v1"
FILTER_SET_VERSION = 1

INTERNET_SETTINGS_PATH = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

PROXY_VALUE_NAMES: tuple[str, ...] = (
    "ProxyEnable",
    "ProxyServer",
    "AutoConfigURL",
    "ProxyOverride",
    "AutoDetect",
)

RECOMMENDED_CSV_COLUMNS: tuple[str, ...] = (
    "Time of Day",
    "Process Name",
    "PID",
    "Operation",
    "Path",
    "Result",
    "Detail",
)


@dataclass(frozen=True)
class ProcmonFilterRule:
    """One Include rule operators add in Process Monitor Filter dialog."""

    column: str
    relation: str
    value: str
    action: str = "Include"
    rationale: str = ""

    def to_dict(self) -> dict[str, str]:
        """To dict.

        Args:
            None.

        Returns:
            The dict[str, str] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "column": self.column,
            "relation": self.relation,
            "value": self.value,
            "action": self.action,
            "rationale": self.rationale,
        }


def build_procmon_filter_rules() -> list[ProcmonFilterRule]:
    """Return Include rules for WinINET proxy ``RegSetValue`` capture.

    Returns:
        Ordered rules: one Operation rule plus Path-contains rules per proxy value.
    """

    rules: list[ProcmonFilterRule] = [
        ProcmonFilterRule(
            column="Operation",
            relation="is",
            value="RegSetValue",
            rationale="Registry value writes only (drops reads/enumerates).",
        ),
    ]
    for name in PROXY_VALUE_NAMES:
        rules.append(
            ProcmonFilterRule(
                column="Path",
                relation="contains",
                value=rf"Internet Settings\{name}",
                rationale=f"WinINET {name} under Internet Settings.",
            )
        )
    return rules


def procmon_filter_set_payload() -> dict[str, Any]:
    """Canonical JSON payload for the shipped Procmon filter set."""

    rules = build_procmon_filter_rules()
    return {
        "filter_set_id": FILTER_SET_ID,
        "version": FILTER_SET_VERSION,
        "purpose": (
            "Capture successful RegSetValue events on WinINET proxy keys for "
            "writer-proof import via proxy-attribution --procmon."
        ),
        "registry_root": INTERNET_SETTINGS_PATH,
        "proxy_values": list(PROXY_VALUE_NAMES),
        "procmon_ui": {
            "drop_filtered_events": True,
            "capture_note": (
                "Run Procmon elevated. Enable Drop Filtered Events after adding "
                "Include rules so only matching rows remain."
            ),
            "export": (
                "File → Save → CSV (or Events displayed using current filter). "
                "Include recommended columns."
            ),
        },
        "recommended_csv_columns": list(RECOMMENDED_CSV_COLUMNS),
        "rules": [r.to_dict() for r in rules],
        "import_commands": [
            "python -m src proxy-attribution --procmon path\\to\\export.csv --json",
            "python -m src proxy-watch --interval 3 --soak-minutes 2 --evidence-csv path\\to\\export.csv",
            "python -m src proxy registry-writer-proof --json --procmon-csv path\\to\\export.csv",
        ],
        "limitations": [
            "Procmon must be running before the rewrite; missed windows yield empty CSV.",
            "RegSetValue rows are strong local evidence, not intent or malware attribution.",
            "Listener correlation (netstat) is not registry-writer proof.",
            "Session-0 writers may appear with limited path/cmdline in other tools; Procmon still shows Image/PID when captured.",
        ],
    }


def format_procmon_filter_instructions() -> str:
    """Human-readable Filter → Add recipe for operators."""

    payload = procmon_filter_set_payload()
    lines: list[str] = [
        f"Procmon filter set: {payload['filter_set_id']} (v{payload['version']})",
        "",
        "1. Start Process Monitor as Administrator.",
        "2. Filter -> Filter... (Ctrl+L).",
        "3. Clear existing rules if needed, then Add each Include rule below.",
        "4. Check 'Drop Filtered Events'.",
        "5. Reproduce the proxy rewrite (open LinkedIn / wait for reverter).",
        "6. File -> Save -> CSV with columns: " + ", ".join(RECOMMENDED_CSV_COLUMNS),
        "7. Import:",
        "   python -m src proxy-attribution --procmon <export.csv> --json",
        "",
        f"Registry root: {INTERNET_SETTINGS_PATH}",
        "",
        "Filter rules (Filter -> Add):",
    ]
    for i, rule in enumerate(payload["rules"], start=1):
        lines.append(
            f"  {i}. {rule['column']} {rule['relation']} {rule['value']} -> {rule['action']}"
            + (f"  # {rule['rationale']}" if rule.get("rationale") else "")
        )
    lines.extend(
        [
            "",
            "Limitations:",
            *[f"  - {item}" for item in payload["limitations"]],
            "",
            "Docs: docs/procmon_proxy_filter.md",
        ]
    )
    return "\n".join(lines) + "\n"


def default_filter_set_path(repo_root: Path) -> Path:
    """Default on-disk JSON path under ``telemetry/procmon/``."""

    return repo_root / "telemetry" / "procmon" / "wininet_proxy_regsetvalue.filter.json"


def export_procmon_filter_set(path: Path) -> Path:
    """Write the canonical filter set JSON to *path* (parents created)."""

    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(procmon_filter_set_payload(), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path

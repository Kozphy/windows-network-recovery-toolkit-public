"""Investigation vocabulary, audit paths, and epistemic guardrails.

Module responsibility:
    Centralize stable string constants so investigation, audit, and report renderers
    share the same limitation text and schema version tokens.

System placement:
    Imported by ``hypotheses``, ``workflow``, ``report``, and ``audit`` under
    ``src.proxy_investigation``. Not invoked by ``src.proxy_guard`` execution paths.

Key invariants:
    * ``MALWARE_FORBIDDEN`` and ``ATTRIBUTION_LISTENER_ONLY`` must appear in operator-facing output.
    * ``SCHEMA_VERSION`` changes require coordinated JSONL consumer updates.

Side effects:
    None.

Audit Notes:
    * Do not weaken ``MALWARE_FORBIDDEN`` without security review — reports inherit it verbatim.
"""

from __future__ import annotations

SCHEMA_VERSION = "proxy_investigation.v1"
ENGINE_VERSION = "2026.05"
AUDIT_JSONL = "logs/proxy_investigation.jsonl"
REPORT_DIR_NAME = "reports/proxy_investigations"

ATTRIBUTION_LISTENER_ONLY = (
    "Listener/process correlation does not prove which process modified WinINET registry values."
)
MALWARE_FORBIDDEN = "Do not label activity as malware or confirmed attack without proof-tier evidence."

DEV_PROCESS_NAMES = frozenset(
    {
        "node.exe",
        "npm.cmd",
        "npm.exe",
        "electron.exe",
        "code.exe",
        "cursor.exe",
        "devenv.exe",
        "python.exe",
        "pnpm.exe",
        "yarn.exe",
    },
)

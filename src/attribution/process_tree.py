"""Document src.attribution.process_tree responsibilities.

Module responsibility:
    Owns attribution helpers that connect process evidence to observed network or proxy changes without asserting causal certainty beyond available evidence.

System placement:
    Used by CLI, API, or platform services that assemble endpoint evidence and governance outputs.

Key invariants:
    Keeps observations, hypotheses, policy decisions, remediation, and audit records separate.

Side effects:
    Importing this module has no intended runtime side effects beyond defining constants, classes, or functions.
"""

from __future__ import annotations

import re
from typing import Any


def parse_simple_process_block(text: str) -> dict[str, Any]:
    """Parse minimal ``wmic process`` / ``gwmi`` styled ``Key=Value`` lines.

    Used with fixture text in tests when live WMI is unavailable.
    """
    out: dict[str, Any] = {}
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, _, v = line.partition("=")
        key = k.strip()
        val = v.strip().rstrip("\r")
        if re.fullmatch(r"-?\d+", val):
            out[key] = int(val)
        elif val.lower() in {"null", "none", "(null)"}:
            out[key] = None
        else:
            out[key] = val
    return out

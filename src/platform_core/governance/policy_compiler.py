"""YAML policy matrix parser."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def compile_policy_matrix(path: Path | str) -> dict[str, Any]:
    """Compile policy matrix.

    Args:
        path: path supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    p = Path(path)
    if not p.is_file():
        return {"rules": [], "source": str(p), "status": "missing"}
    text = p.read_text(encoding="utf-8")
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith(":") and not line.startswith("-"):
            if current:
                rules.append(current)
            current = {"name": line[:-1], "expectations": []}
        elif line.startswith("- ") and current is not None:
            current.setdefault("expectations", []).append(line[2:].strip())
    if current:
        rules.append(current)
    return {"rules": rules, "source": str(p), "status": "compiled", "rule_count": len(rules)}

"""Load trusted-process allowlist for localhost proxy risk downgrade."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - optional at runtime
    yaml = None  # type: ignore[assignment]


@dataclass(frozen=True)
class ProxyAllowlist:
    """Represent proxy allowlist data used by the toolkit.
    
    Attributes:
        trusted_processes: Field or variant describing trusted processes evidence or state.
        trusted_paths: Field or variant describing trusted paths evidence or state.
        trusted_commandline_keywords: Field or variant describing trusted commandline keywords evidence or state.
    
    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """
    trusted_processes: frozenset[str]
    trusted_paths: frozenset[str]
    trusted_commandline_keywords: frozenset[str]

    @classmethod
    def defaults(cls) -> ProxyAllowlist:
        """Defaults.
        
        Args:
            None.
        
        Returns:
            The ProxyAllowlist result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return cls(
            trusted_processes=frozenset({"cursor.exe", "code.exe", "node.exe", "electron.exe"}),
            trusted_paths=frozenset(),
            trusted_commandline_keywords=frozenset(
                {"mcp", "extension", "devserver", "dev-server", "localhost", "proxy"}
            ),
        )


def _expand_path(value: str) -> str:
    expanded = os.path.expandvars(value.strip())
    return expanded.replace("/", "\\").lower().rstrip("\\")


def load_proxy_allowlist(repo_root: Path | None = None) -> ProxyAllowlist:
    """Load ``config/proxy_allowlist.yaml`` or return conservative defaults."""
    root = repo_root or Path.cwd()
    path = root / "config" / "proxy_allowlist.yaml"
    if not path.is_file():
        return ProxyAllowlist.defaults()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ProxyAllowlist.defaults()
    if yaml is not None:
        try:
            blob = yaml.safe_load(text)
        except Exception:
            blob = _parse_minimal_yaml_lists(text)
    else:
        blob = _parse_minimal_yaml_lists(text)
    if not isinstance(blob, dict):
        return ProxyAllowlist.defaults()
    return ProxyAllowlist(
        trusted_processes=frozenset(
            str(x).strip().lower() for x in (blob.get("trusted_processes") or []) if str(x).strip()
        ),
        trusted_paths=frozenset(
            _expand_path(str(x)) for x in (blob.get("trusted_paths") or []) if str(x).strip()
        ),
        trusted_commandline_keywords=frozenset(
            str(x).strip().lower()
            for x in (blob.get("trusted_commandline_keywords") or [])
            if str(x).strip()
        ),
    )


def _parse_minimal_yaml_lists(text: str) -> dict[str, list[str]]:
    """Parse simple list-only YAML without external dependency."""
    out: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith(":") and not line.startswith("- "):
            current = line[:-1].strip()
            out.setdefault(current, [])
            continue
        if line.startswith("- ") and current:
            out[current].append(line[2:].strip())
    return out


def allowlist_match_summary(
    *,
    process_name: str | None,
    executable_path: str | None,
    command_line: str | None,
    allowlist: ProxyAllowlist,
) -> dict[str, Any]:
    """Return which allowlist dimensions matched (for evidence + risk downgrade)."""
    name = (process_name or "").strip().lower()
    path = _expand_path(executable_path or "") if executable_path else ""
    cmd = (command_line or "").lower()
    proc_hit = name in allowlist.trusted_processes if name else False
    path_hit = any(path.startswith(tp) for tp in allowlist.trusted_paths) if path else False
    kw_hits = [kw for kw in allowlist.trusted_commandline_keywords if kw in cmd] if cmd else []
    return {
        "trusted_process": proc_hit,
        "trusted_path_prefix": path_hit,
        "trusted_commandline_keywords": kw_hits,
        "any_match": proc_hit or path_hit or bool(kw_hits),
    }

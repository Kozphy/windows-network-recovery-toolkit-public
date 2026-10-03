"""Fail-closed publication gate for sanitized diagnostic evidence."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from platform_core.privacy import sanitize_evidence_record

_FORBIDDEN_KEY_RE = re.compile(
    r"(?i)^(password|passwd|secret|token|access_token|refresh_token|api_key|authorization|ssid|mac|mac_address)$"
)
_RAW_WINDOWS_USER_RE = re.compile(r"(?i)C:\\Users\\(?!\[redacted\])[^\\\s]+")
_RAW_MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
_CREDENTIAL_RE = re.compile(
    r"(?i)(authorization\s*:\s*bearer\s+(?!\[REDACTED\])\S+|"
    r"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret)\s*[:=]\s*(?!\[REDACTED\])\S+)"
)


@dataclass(frozen=True)
class PublicationDecision:
    """Machine-readable result of the public-evidence policy gate."""

    allowed: bool
    reasons: tuple[str, ...]
    sanitized: dict[str, object]


def _find_forbidden_keys(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if _FORBIDDEN_KEY_RE.match(str(key)) and child not in {
                "[SECRET_REDACTED]",
                "[REDACTED]",
                None,
                "",
            }:
                findings.append(f"unsanitized_sensitive_key:{child_path}")
            findings.extend(_find_forbidden_keys(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            findings.extend(_find_forbidden_keys(child, f"{path}[{index}]"))
    return findings


def evaluate_publication(record: dict[str, object]) -> PublicationDecision:
    """Sanitize and independently inspect an evidence record before publication.

    The gate fails closed: any residual credential, MAC, raw Windows profile path,
    or unsanitized sensitive field blocks publication.
    """
    sanitized = sanitize_evidence_record(record)
    rendered = json.dumps(sanitized, sort_keys=True, ensure_ascii=False)
    reasons = _find_forbidden_keys(sanitized)
    if _RAW_WINDOWS_USER_RE.search(rendered):
        reasons.append("raw_windows_user_path")
    if _RAW_MAC_RE.search(rendered):
        reasons.append("raw_mac_address")
    if _CREDENTIAL_RE.search(rendered):
        reasons.append("credential_pattern")
    unique = tuple(sorted(set(reasons)))
    return PublicationDecision(allowed=not unique, reasons=unique, sanitized=sanitized)


def require_safe_to_publish(record: dict[str, object]) -> dict[str, object]:
    """Return sanitized evidence or raise instead of publishing unsafe data."""
    decision = evaluate_publication(record)
    if not decision.allowed:
        raise ValueError("SAFE_TO_PUBLISH=false: " + ", ".join(decision.reasons))
    return decision.sanitized

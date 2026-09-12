"""Text guardrails for AI-generated explanations — advisory only."""

from __future__ import annotations

import re
from dataclasses import dataclass

_UNSAFE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("malware confirmed", re.compile(r"malware\s+confirmed", re.I)),
    ("malware detected", re.compile(r"malware\s+detected", re.I)),
    ("mitm confirmed", re.compile(r"mitm\s+confirmed", re.I)),
    ("compromised", re.compile(r"\bcompromised\b", re.I)),
    ("safe to disable automatically", re.compile(r"safe\s+to\s+disable\s+automatically", re.I)),
    ("kill the process", re.compile(r"kill\s+the\s+process", re.I)),
    ("reset the firewall", re.compile(r"reset\s+the\s+firewall", re.I)),
    ("audit opinion", re.compile(r"audit\s+opinion", re.I)),
    ("ai approved remediation", re.compile(r"ai\s+approved\s+remediation", re.I)),
    ("autonomous repair", re.compile(r"autonomous\s+repair", re.I)),
    ("formal audit", re.compile(r"formal\s+audit", re.I)),
    ("authorize registry", re.compile(r"authorize\s+registry", re.I)),
]

_SAFE_REWRITE_TEMPLATE = (
    "Evidence summary for management review: classification reflects endpoint reliability "
    "triage only. Limitations apply — this is not malware detection, not MITM confirmation, "
    "and not a formal audit opinion. Remediation requires human approval and typed confirmation."
)


@dataclass
class ExplanationValidationResult:
    """Represent the explanation validation result type.

    Key fields:
        is_safe: Structured value carried by this type.
        violations: Structured value carried by this type.
        recommended_rewrite: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    is_safe: bool
    violations: list[str]
    recommended_rewrite: str | None = None


def validate_explanation_text(text: str) -> ExplanationValidationResult:
    """Scan explanation text for unsafe authority or security-product claims."""
    violations: list[str] = []
    for label, pattern in _UNSAFE_PATTERNS:
        if pattern.search(text):
            violations.append(label)
    if violations:
        return ExplanationValidationResult(
            is_safe=False,
            violations=violations,
            recommended_rewrite=_SAFE_REWRITE_TEMPLATE,
        )
    return ExplanationValidationResult(is_safe=True, violations=[], recommended_rewrite=None)


def sanitize_explanation_text(text: str) -> str:
    """Return safe text — original if valid, otherwise recommended rewrite."""
    result = validate_explanation_text(text)
    if result.is_safe:
        return text
    return result.recommended_rewrite or _SAFE_REWRITE_TEMPLATE

"""Load and validate YAML policy profiles for proxy / remediation gates."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

PolicyGate = Literal["allow", "observe", "preview", "require_confirmation", "block"]

_VALID_GATES = frozenset({"allow", "observe", "preview", "require_confirmation", "block"})


class PolicyRule(BaseModel):
    """Represent PolicyRule data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    id: str
    match: str
    gate: PolicyGate
    description: str = ""


class PolicyDocument(BaseModel):
    """Represent PolicyDocument data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    version: str = "1"
    name: str
    description: str = ""
    rules: list[PolicyRule] = Field(default_factory=list)
    default_gate: PolicyGate = "preview"

    @field_validator("version")
    @classmethod
    def _version_supported(cls, v: str) -> str:
        if str(v).strip() not in ("1", "1.0"):
            raise ValueError("unsupported policy version — expected 1")
        return str(v).strip()


def _parse_yaml(text: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError:
        yaml = None  # type: ignore[assignment]
    if yaml is not None:
        blob = yaml.safe_load(text)
        return blob if isinstance(blob, dict) else {}
    return _parse_minimal_policy(text)


def _parse_minimal_policy(text: str) -> dict[str, Any]:
    """Parse simple policy YAML without PyYAML (lists + key/value)."""
    out: dict[str, Any] = {"rules": []}
    current_rule: dict[str, str] | None = None
    in_rules = False
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "rules:":
            in_rules = True
            continue
        if not in_rules and ":" in stripped and not stripped.startswith("- "):
            key, _, val = stripped.partition(":")
            out[key.strip()] = val.strip().strip('"').strip("'")
            continue
        if stripped.startswith("- id:") or stripped.startswith("- match:"):
            if current_rule:
                out["rules"].append(current_rule)
            current_rule = {}
        if current_rule is not None and ":" in stripped:
            part = stripped.lstrip("- ").strip()
            key, _, val = part.partition(":")
            current_rule[key.strip()] = val.strip().strip('"').strip("'")
    if current_rule:
        out["rules"].append(current_rule)
    return out


def load_policy_document(path: Path) -> PolicyDocument:
    """Load policy document for toolkit workflows.

    Args:
        path: Value supplied by the caller for path.

    Returns:
        Computed result for the requested operation.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    text = path.read_text(encoding="utf-8")
    blob = _parse_yaml(text)
    rules_raw = blob.get("rules") or []
    rules: list[PolicyRule] = []
    for row in rules_raw:
        if isinstance(row, dict) and row.get("id") and row.get("match"):
            gate = str(row.get("gate") or blob.get("default_gate") or "preview").lower()
            if gate not in _VALID_GATES:
                raise ValueError(f"invalid gate {gate!r} in rule {row.get('id')}")
            rules.append(
                PolicyRule(
                    id=str(row["id"]),
                    match=str(row["match"]),
                    gate=gate,  # type: ignore[arg-type]
                    description=str(row.get("description") or ""),
                )
            )
    doc = PolicyDocument(
        version=str(blob.get("version") or "1"),
        name=str(blob.get("name") or path.stem),
        description=str(blob.get("description") or ""),
        rules=rules,
        default_gate=str(blob.get("default_gate") or "preview").lower(),  # type: ignore[arg-type]
    )
    return doc


def validate_policy_document(path: Path) -> list[str]:
    """Return validation errors; empty list means valid."""
    errors: list[str] = []
    if not path.is_file():
        return [f"file not found: {path}"]
    try:
        doc = load_policy_document(path)
    except Exception as exc:
        return [str(exc)]
    if not doc.name:
        errors.append("policy name is required")
    if not doc.rules:
        errors.append("at least one rule is required")
    seen: set[str] = set()
    for rule in doc.rules:
        if rule.id in seen:
            errors.append(f"duplicate rule id: {rule.id}")
        seen.add(rule.id)
        if rule.gate not in _VALID_GATES:
            errors.append(f"rule {rule.id}: invalid gate {rule.gate}")
    return errors


def resolve_policy_gate(
    doc: PolicyDocument,
    *,
    classification: str | None = None,
    risk_level: str | None = None,
    external_proxy: bool = False,
) -> PolicyGate:
    """Map incident context to a policy gate using first matching rule."""
    haystacks = [
        (classification or "").lower(),
        (risk_level or "").lower(),
        "external_proxy" if external_proxy else "localhost_proxy",
    ]
    for rule in doc.rules:
        needle = rule.match.lower()
        if any(needle in h or h in needle for h in haystacks if h):
            return rule.gate
    return doc.default_gate

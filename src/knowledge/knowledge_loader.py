"""Deterministic YAML/JSON knowledge loading with schema enforcement.

Loads versioned knowledge bundles from single files or merged directories.
Falls back to a minimal YAML parser when PyYAML is not installed.

Validation boundaries:
    - ``schema_version`` must be in ``ALLOWED_SCHEMA_VERSIONS``.
    - ``knowledge_version`` is required.
    - At least one entry mapping is required.

Output guarantees:
    - :func:`bundle_content_digest` is stable for identical bundle content.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .knowledge_models import (
    ALLOWED_SCHEMA_VERSIONS,
    KNOWLEDGE_SCHEMA_V1,
    RESERVED_TOP_LEVEL_KEYS,
    KnowledgeBundle,
    KnowledgeEntry,
)

try:
    import yaml
except ImportError:  # pragma: no cover - optional at runtime
    yaml = None  # type: ignore[assignment]


def _parse_text_to_dict(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        raise ValueError("knowledge document is empty")
    if yaml is not None:
        loaded = yaml.safe_load(text)
    elif stripped.startswith("{"):
        loaded = json.loads(text)
    else:
        loaded = _parse_minimal_yaml_mapping(text)
    if not isinstance(loaded, dict):
        raise ValueError("knowledge document root must be a mapping")
    return loaded


def _parse_minimal_yaml_mapping(text: str) -> dict[str, Any]:
    """Parse a constrained YAML subset without PyYAML (lists + nested maps)."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    current_key: str | None = None

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        line = raw_line.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        container = stack[-1][1]

        if line.startswith("- "):
            if current_key is None:
                raise ValueError("list item without parent key")
            value = _parse_scalar(line[2:].strip())
            existing = container.get(current_key)
            if existing is None:
                container[current_key] = [value]
            elif isinstance(existing, list):
                existing.append(value)
            else:
                raise ValueError(f"cannot append list item to non-list key {current_key!r}")
            continue

        if ":" not in line:
            raise ValueError(f"invalid knowledge yaml line: {raw_line!r}")

        key, _, remainder = line.partition(":")
        key = key.strip()
        value_text = remainder.strip()

        if value_text:
            container[key] = _parse_scalar(value_text)
            current_key = key
            continue

        new_map: dict[str, Any] = {}
        container[key] = new_map
        stack.append((indent, new_map))
        current_key = key

    return root


def _parse_scalar(value: str) -> Any:
    if not value:
        return ""
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    low = value.lower()
    if low in {"true", "false"}:
        return low == "true"
    if low in {"null", "~"}:
        return None
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _normalize_entries_blob(entries_blob: dict[str, Any]) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for entry_id, payload in sorted(entries_blob.items()):
        if not isinstance(payload, dict):
            raise ValueError(f"entry {entry_id!r} must be a mapping")
        row = dict(payload)
        row["entry_id"] = entry_id
        normalized[entry_id] = row
    return normalized


def _extract_bundle_fields(document: dict[str, Any]) -> tuple[str, str, dict[str, dict[str, Any]]]:
    schema_version = str(document.get("schema_version") or KNOWLEDGE_SCHEMA_V1)
    if schema_version not in ALLOWED_SCHEMA_VERSIONS:
        raise ValueError(f"unsupported schema_version: {schema_version!r}")

    knowledge_version = document.get("knowledge_version")
    if not knowledge_version:
        raise ValueError("knowledge_version is required")

    entries_blob = document.get("entries")
    if entries_blob is None:
        entries_blob = {
            key: value
            for key, value in document.items()
            if key not in RESERVED_TOP_LEVEL_KEYS and isinstance(value, dict)
        }
    if not isinstance(entries_blob, dict):
        raise ValueError("entries must be a mapping")
    if not entries_blob:
        raise ValueError("knowledge document must contain at least one entry")

    return schema_version, str(knowledge_version), _normalize_entries_blob(entries_blob)


def parse_knowledge_document(document: dict[str, Any], *, source_path: str = "") -> KnowledgeBundle:
    """Validate and normalize a parsed YAML/JSON document into a :class:`KnowledgeBundle`."""
    schema_version, knowledge_version, entries_blob = _extract_bundle_fields(document)
    entries = {
        entry_id: KnowledgeEntry.model_validate(payload) for entry_id, payload in sorted(entries_blob.items())
    }
    return KnowledgeBundle(
        schema_version=schema_version,  # type: ignore[arg-type]
        knowledge_version=knowledge_version,
        source_path=source_path,
        entries=entries,
    )


def load_knowledge_text(text: str, *, source_path: str = "") -> KnowledgeBundle:
    """Load a knowledge bundle from YAML or JSON text."""
    return parse_knowledge_document(_parse_text_to_dict(text), source_path=source_path)


def load_knowledge_path(path: Path) -> KnowledgeBundle:
    """Load a single knowledge file (``.yaml``, ``.yml``, or ``.json``)."""
    if not path.is_file():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8")
    return load_knowledge_text(text, source_path=str(path.resolve()))


def load_knowledge_directory(directory: Path) -> KnowledgeBundle:
    """Load and merge knowledge files from a directory in deterministic sorted order."""
    if not directory.is_dir():
        raise FileNotFoundError(directory)

    files = sorted(
        p
        for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() in {".yaml", ".yml", ".json"}
    )
    if not files:
        raise ValueError(f"no knowledge files found in {directory}")

    merged_entries: dict[str, KnowledgeEntry] = {}
    knowledge_version = ""
    schema_version = KNOWLEDGE_SCHEMA_V1
    source_paths: list[str] = []

    for file_path in files:
        bundle = load_knowledge_path(file_path)
        schema_version = bundle.schema_version
        knowledge_version = bundle.knowledge_version
        source_paths.append(bundle.source_path)
        merged_entries.update(bundle.entries)

    return KnowledgeBundle(
        schema_version=schema_version,  # type: ignore[arg-type]
        knowledge_version=knowledge_version,
        source_path="|".join(source_paths),
        entries=dict(sorted(merged_entries.items())),
    )


def bundle_to_canonical_dict(bundle: KnowledgeBundle) -> dict[str, Any]:
    """Dump bundle to a JSON-safe dict with sorted entry keys."""
    return bundle.model_dump(mode="json")


def canonical_bundle_json(bundle: KnowledgeBundle) -> str:
    """Serialize bundle deterministically for replay digests."""
    return json.dumps(bundle_to_canonical_dict(bundle), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def bundle_content_digest(bundle: KnowledgeBundle) -> str:
    """SHA-256 digest of canonical bundle JSON."""
    return hashlib.sha256(canonical_bundle_json(bundle).encode("utf-8")).hexdigest()


def default_knowledge_path(repo_root: Path | None = None) -> Path:
    """Return default bundled knowledge path under ``knowledge/``."""
    root = repo_root or Path.cwd()
    return root / "knowledge" / "endpoint_reliability.yaml"

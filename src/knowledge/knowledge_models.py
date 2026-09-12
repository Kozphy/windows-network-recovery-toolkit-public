"""Versioned knowledge documents — reasoning facts separated from executable code."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

KNOWLEDGE_SCHEMA_V1 = "knowledge.v1"
ALLOWED_SCHEMA_VERSIONS: frozenset[str] = frozenset({KNOWLEDGE_SCHEMA_V1})
ENTRY_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
RESERVED_TOP_LEVEL_KEYS = frozenset({"schema_version", "knowledge_version", "entries", "source_path"})


class KnowledgeEntry(BaseModel):
    """Single replayable knowledge fact used by deterministic reasoning."""

    entry_id: str
    category: str = Field(min_length=1)
    common_causes: list[str] = Field(default_factory=list)
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("entry_id")
    @classmethod
    def _validate_entry_id(cls, value: str) -> str:
        if not ENTRY_ID_PATTERN.match(value):
            raise ValueError(f"entry_id must match {ENTRY_ID_PATTERN.pattern!r}: {value!r}")
        return value

    @field_validator("common_causes", "tags", "recommended_checks")
    @classmethod
    def _strip_string_lists(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if str(item).strip()]


class KnowledgeBundle(BaseModel):
    """Versioned bundle of knowledge entries loaded from YAML/JSON."""

    schema_version: Literal["knowledge.v1"] = KNOWLEDGE_SCHEMA_V1
    knowledge_version: str = Field(min_length=1)
    source_path: str = ""
    entries: dict[str, KnowledgeEntry] = Field(default_factory=dict)

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, value: str) -> str:
        if value not in ALLOWED_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported schema_version: {value!r}")
        return value

    @model_validator(mode="after")
    def _entry_keys_match_ids(self) -> KnowledgeBundle:
        for key, entry in self.entries.items():
            if key != entry.entry_id:
                raise ValueError(f"entry key {key!r} does not match entry_id {entry.entry_id!r}")
        return self


class KnowledgeRegistrySnapshot(BaseModel):
    """Immutable registry view for audit and replay."""

    schema_version: str = KNOWLEDGE_SCHEMA_V1
    knowledge_version: str
    source_paths: list[str] = Field(default_factory=list)
    entry_ids: list[str] = Field(default_factory=list)
    content_digest: str
    entries: dict[str, KnowledgeEntry] = Field(default_factory=dict)

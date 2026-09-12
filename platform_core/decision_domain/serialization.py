"""Deterministic serialization and JSON Schema generation for decision domain models."""

from __future__ import annotations

import hashlib
import json
from typing import Any, TypeVar

from pydantic import BaseModel

from .models import (
    Decision,
    DecisionContext,
    DecisionEvidence,
    DecisionExplanation,
    DecisionOption,
    DecisionOutcome,
    DecisionRisk,
)

T = TypeVar("T", bound=BaseModel)

_SCHEMA_VERSION = "decision_domain.schema_bundle.v1"


def canonical_json_dumps(payload: Any) -> str:
    """Serialize *payload* to a stable JSON string (sorted keys, compact separators)."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def model_to_canonical_dict(model: BaseModel) -> dict[str, Any]:
    """Dump a Pydantic model to a JSON-safe dict suitable for canonical hashing."""
    return model.model_dump(mode="json")


def serialize_decision(decision: Decision) -> str:
    """Return deterministic JSON for a :class:`Decision`."""
    return canonical_json_dumps(model_to_canonical_dict(decision))


def decision_content_digest(decision: Decision) -> str:
    """SHA-256 hex digest of canonical decision JSON (replay / audit integrity)."""
    return hashlib.sha256(serialize_decision(decision).encode("utf-8")).hexdigest()


def parse_decision(payload: dict[str, Any] | str) -> Decision:
    """Parse a decision from a dict or canonical JSON string."""
    if isinstance(payload, str):
        data = json.loads(payload)
    else:
        data = payload
    return Decision.model_validate(data)


def model_json_schema(model: type[T]) -> dict[str, Any]:
    """Return JSON Schema for a decision-domain Pydantic model."""
    return model.model_json_schema()


def decision_domain_schema_bundle() -> dict[str, Any]:
    """Return JSON Schemas for all decision-domain models in one bundle."""
    models: dict[str, type[BaseModel]] = {
        "Decision": Decision,
        "DecisionContext": DecisionContext,
        "DecisionEvidence": DecisionEvidence,
        "DecisionExplanation": DecisionExplanation,
        "DecisionOption": DecisionOption,
        "DecisionOutcome": DecisionOutcome,
        "DecisionRisk": DecisionRisk,
    }
    return {
        "schema_bundle_version": _SCHEMA_VERSION,
        "models": {name: model_json_schema(cls) for name, cls in models.items()},
    }

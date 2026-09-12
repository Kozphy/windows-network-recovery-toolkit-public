"""Knowledge layer — versioned reasoning facts separated from executable code."""

from .knowledge_loader import (
    bundle_content_digest,
    bundle_to_canonical_dict,
    canonical_bundle_json,
    default_knowledge_path,
    load_knowledge_directory,
    load_knowledge_path,
    load_knowledge_text,
    parse_knowledge_document,
)
from .knowledge_models import (
    ALLOWED_SCHEMA_VERSIONS,
    KNOWLEDGE_SCHEMA_V1,
    KnowledgeBundle,
    KnowledgeEntry,
    KnowledgeRegistrySnapshot,
)
from .knowledge_registry import KnowledgeRegistry

__all__ = [
    "ALLOWED_SCHEMA_VERSIONS",
    "KNOWLEDGE_SCHEMA_V1",
    "KnowledgeBundle",
    "KnowledgeEntry",
    "KnowledgeRegistry",
    "KnowledgeRegistrySnapshot",
    "bundle_content_digest",
    "bundle_to_canonical_dict",
    "canonical_bundle_json",
    "default_knowledge_path",
    "load_knowledge_directory",
    "load_knowledge_path",
    "load_knowledge_text",
    "parse_knowledge_document",
]

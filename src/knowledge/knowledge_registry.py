"""In-memory knowledge registry — deterministic lookup and replay snapshots.

Wraps a validated :class:`KnowledgeBundle` with digest-backed lookup helpers.
Does not hot-reload files — construct a new registry after knowledge file changes.
"""

from __future__ import annotations

from pathlib import Path

from .knowledge_loader import (
    bundle_content_digest,
    default_knowledge_path,
    load_knowledge_directory,
    load_knowledge_path,
    load_knowledge_text,
)
from .knowledge_models import KnowledgeBundle, KnowledgeEntry, KnowledgeRegistrySnapshot


class KnowledgeRegistry:
    """Replayable registry over a validated :class:`KnowledgeBundle`."""

    def __init__(self, bundle: KnowledgeBundle, *, content_digest: str | None = None) -> None:
        """Initialize the object with caller supplied state.
        
        Args:
            bundle: The bundle value supplied by the caller.
            content_digest: The content digest value supplied by the caller.
        
        Returns:
            None.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        self._bundle = bundle
        self._digest = content_digest or bundle_content_digest(bundle)
        self._entries = dict(sorted(bundle.entries.items()))

    @classmethod
    def from_bundle(cls, bundle: KnowledgeBundle) -> KnowledgeRegistry:
        """From bundle.
        
        Args:
            bundle: The bundle value supplied by the caller.
        
        Returns:
            The KnowledgeRegistry result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return cls(bundle)

    @classmethod
    def from_path(cls, path: Path) -> KnowledgeRegistry:
        """From path.
        
        Args:
            path: Filesystem path used by the operation.
        
        Returns:
            The KnowledgeRegistry result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return cls(load_knowledge_path(path))

    @classmethod
    def from_directory(cls, directory: Path) -> KnowledgeRegistry:
        """From directory.
        
        Args:
            directory: The directory value supplied by the caller.
        
        Returns:
            The KnowledgeRegistry result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return cls(load_knowledge_directory(directory))

    @classmethod
    def from_text(cls, text: str, *, source_path: str = "") -> KnowledgeRegistry:
        """From text.
        
        Args:
            text: The text value supplied by the caller.
            source_path: Filesystem path used by the operation.
        
        Returns:
            The KnowledgeRegistry result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return cls(load_knowledge_text(text, source_path=source_path))

    @classmethod
    def from_default(cls, repo_root: Path | None = None) -> KnowledgeRegistry:
        """From default.
        
        Args:
            repo_root: Repository root used to resolve fixtures, reports, or local state.
        
        Returns:
            The KnowledgeRegistry result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return cls.from_path(default_knowledge_path(repo_root))

    @property
    def bundle(self) -> KnowledgeBundle:
        """Bundle.
        
        Args:
            None.
        
        Returns:
            The KnowledgeBundle result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return self._bundle

    @property
    def knowledge_version(self) -> str:
        """Knowledge version.
        
        Args:
            None.
        
        Returns:
            The str result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return self._bundle.knowledge_version

    @property
    def schema_version(self) -> str:
        """Schema version.
        
        Args:
            None.
        
        Returns:
            The str result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return self._bundle.schema_version

    def content_digest(self) -> str:
        """Content digest.
        
        Args:
            None.
        
        Returns:
            The str result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return self._digest

    def entry_ids(self) -> list[str]:
        """Entry ids.
        
        Args:
            None.
        
        Returns:
            The list[str] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return list(self._entries.keys())

    def categories(self) -> list[str]:
        """Categories.
        
        Args:
            None.
        
        Returns:
            The list[str] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return sorted({entry.category for entry in self._entries.values()})

    def get(self, entry_id: str) -> KnowledgeEntry:
        """Get.
        
        Args:
            entry_id: The entry id value supplied by the caller.
        
        Returns:
            The KnowledgeEntry result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        try:
            return self._entries[entry_id]
        except KeyError as exc:
            raise KeyError(f"unknown knowledge entry: {entry_id}") from exc

    def try_get(self, entry_id: str) -> KnowledgeEntry | None:
        """Try get.
        
        Args:
            entry_id: The entry id value supplied by the caller.
        
        Returns:
            The KnowledgeEntry | None result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return self._entries.get(entry_id)

    def list_by_category(self, category: str) -> list[KnowledgeEntry]:
        """List by category.
        
        Args:
            category: The category value supplied by the caller.
        
        Returns:
            The list[KnowledgeEntry] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        cat = category.strip().lower()
        return [entry for entry in self._entries.values() if entry.category.lower() == cat]

    def common_causes_for(self, entry_id: str) -> list[str]:
        """Common causes for.
        
        Args:
            entry_id: The entry id value supplied by the caller.
        
        Returns:
            The list[str] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return list(self.get(entry_id).common_causes)

    def snapshot(self) -> KnowledgeRegistrySnapshot:
        """Snapshot.
        
        Args:
            None.
        
        Returns:
            The KnowledgeRegistrySnapshot result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return KnowledgeRegistrySnapshot(
            knowledge_version=self._bundle.knowledge_version,
            source_paths=[self._bundle.source_path] if self._bundle.source_path else [],
            entry_ids=self.entry_ids(),
            content_digest=self._digest,
            entries=self._entries,
        )

"""Domain adapter interface — collect events and evidence only."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from src.platform.models import DomainName, EvidenceItem, NormalizedEvent

FIXTURES_ROOT = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "domains"


class DomainAdapter(ABC):
    """Domains supply events and evidence; shared engines handle reasoning."""

    domain_name: DomainName

    @property
    def fixture_dir(self) -> Path:
        """Fixture dir.
        
        Args:
            None.
        
        Returns:
            The Path result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return FIXTURES_ROOT / self.domain_name

    def list_fixtures(self) -> list[str]:
        """List fixtures.
        
        Args:
            None.
        
        Returns:
            The list[str] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        if not self.fixture_dir.is_dir():
            return []
        return sorted(p.name for p in self.fixture_dir.glob("*.json"))

    def load_fixture_blob(self, name: str | None = None) -> dict[str, Any]:
        """Load fixture blob.
        
        Args:
            name: The name value supplied by the caller.
        
        Returns:
            The dict[str, Any] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        files = self.list_fixtures()
        if not files:
            raise FileNotFoundError(f"No fixtures for {self.domain_name}")
        fname = name or files[0]
        return json.loads((self.fixture_dir / fname).read_text(encoding="utf-8"))

    def collect_events(self, fixture_name: str | None = None) -> list[NormalizedEvent]:
        """Collect events.
        
        Args:
            fixture_name: The fixture name value supplied by the caller.
        
        Returns:
            The list[NormalizedEvent] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        fname = fixture_name or (self.list_fixtures()[0] if self.list_fixtures() else None)
        blob = self.load_fixture_blob(fname)
        event_data = blob.get("event") or blob
        ev = NormalizedEvent.model_validate(event_data)
        meta = dict(ev.metadata)
        if fname:
            meta["fixture"] = fname
        return [ev.model_copy(update={"metadata": meta})]

    @abstractmethod
    def build_evidence(self, event: NormalizedEvent) -> list[EvidenceItem]:
        """Build evidence.
        
        Args:
            event: Evidence or domain record being processed.
        
        Returns:
            The list[EvidenceItem] result produced by the operation.
        
        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

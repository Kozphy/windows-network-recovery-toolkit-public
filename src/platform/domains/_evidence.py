"""Document src.platform.domains._evidence responsibilities.

Module responsibility:
    Owns platform orchestration models, adapters, or compatibility helpers without asserting causal certainty beyond available evidence.

System placement:
    Used by CLI, API, or platform services that assemble endpoint evidence and governance outputs.

Key invariants:
    Keeps observations, hypotheses, policy decisions, remediation, and audit records separate.

Side effects:
    Importing this module has no intended runtime side effects beyond defining constants, classes, or functions.
"""

from __future__ import annotations

from src.platform.domains.base import DomainAdapter
from src.platform.models import EvidenceItem, NormalizedEvent


class FixtureEvidenceAdapter(DomainAdapter):
    """Default build_evidence from fixture JSON."""

    def build_evidence(self, event: NormalizedEvent) -> list[EvidenceItem]:
        """Build evidence.
        
        Args:
            event: Evidence or domain record being processed.
        
        Returns:
            The list[EvidenceItem] result produced by the operation.
        
        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        rows = self.load_fixture_blob(event.metadata.get("fixture")).get("evidence") or []
        out: list[EvidenceItem] = []
        for row in rows:
            data = dict(row)
            data["event_id"] = event.event_id
            data.setdefault("timestamp_utc", event.timestamp_utc)
            out.append(EvidenceItem.model_validate(data))
        return out

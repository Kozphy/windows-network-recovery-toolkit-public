"""Load hypotheses and decisions from fixture JSON (shared across domains)."""

from __future__ import annotations

from src.platform.domains.base import DomainAdapter
from src.platform.models import DecisionOption, Hypothesis, NormalizedEvent


def _blob(adapter: DomainAdapter, event: NormalizedEvent) -> dict:
    return adapter.load_fixture_blob(event.metadata.get("fixture"))


def load_hypotheses(adapter: DomainAdapter, event: NormalizedEvent) -> list[Hypothesis]:
    """Load hypotheses.

    Args:
        adapter: The adapter value supplied by the caller.
        event: Evidence or domain record being processed.

    Returns:
        The list[Hypothesis] result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    rows = _blob(adapter, event).get("hypotheses") or []
    out: list[Hypothesis] = []
    for row in rows:
        data = dict(row)
        data["event_id"] = event.event_id
        out.append(Hypothesis.model_validate(data))
    return out


def load_decisions(adapter: DomainAdapter, event: NormalizedEvent) -> list[DecisionOption]:
    """Load decisions.

    Args:
        adapter: The adapter value supplied by the caller.
        event: Evidence or domain record being processed.

    Returns:
        The list[DecisionOption] result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.

    Audit Notes:
        Preserves observation, policy, and audit boundaries established by the caller.
    """
    rows = _blob(adapter, event).get("decisions") or []
    out: list[DecisionOption] = []
    for row in rows:
        data = dict(row)
        data["event_id"] = event.event_id
        out.append(DecisionOption.model_validate(data))
    return out

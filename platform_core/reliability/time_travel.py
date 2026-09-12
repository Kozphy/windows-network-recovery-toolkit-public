"""Time-travel replay — reconstruct state, evidence, and decisions from historical events."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from platform_core import storage

from .models import NormalizedPlatformEvent, PlatformDecisionRecord


class TimeTravelReplay:
    """Reconstruct platform state at a point in time without re-probing the host."""

    def __init__(
        self,
        *,
        original: PlatformDecisionRecord,
        replayed: PlatformDecisionRecord,
        parity: dict[str, bool],
    ) -> None:
        """Initialize the TimeTravelReplay instance.

        Args:
            original: Value supplied by the caller for original.
            replayed: Value supplied by the caller for replayed.
            parity: Value supplied by the caller for parity.

        Returns:
            None.

        Side effects:
            Initializes instance state only.
        """
        self.original = original
        self.replayed = replayed
        self.parity = parity

    def to_jsonable(self) -> dict[str, Any]:
        """Return a serialized to jsonable representation.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return {
            "run_id": self.original.run_id,
            "parity": self.parity,
            "original_policy": self.original.policy_outcome,
            "replayed_policy": self.replayed.policy_outcome,
            "original_state_path": self.original.state_path,
            "replayed_state_path": self.replayed.state_path,
            "original_hypothesis": self.original.accepted_hypothesis,
            "replayed_hypothesis": self.replayed.accepted_hypothesis,
        }

    @classmethod
    def load_and_replay(cls, run_id: str, *, path: Path | None = None) -> TimeTravelReplay:
        """Load and replay for toolkit workflows.

        Args:
            run_id: Value supplied by the caller for run id.
            path: Value supplied by the caller for path.

        Returns:
            Computed result for the requested operation.

        Side effects:
            May perform the I/O or state updates implied by the operation.
        """
        decisions_path = path or storage.platform_data_dir() / "platform_decisions.jsonl"
        original: PlatformDecisionRecord | None = None
        for row in storage.iter_jsonl(decisions_path):
            if str(row.get("run_id") or "") == run_id:
                original = PlatformDecisionRecord(**row)
                break
        if original is None:
            raise KeyError(f"Decision run {run_id} not found")

        events_path = (
            path.parent / "platform_events.jsonl"
            if path is not None
            else storage.platform_data_dir() / "platform_events.jsonl"
        )
        observations: list[dict[str, Any]] = []
        for row in storage.iter_jsonl(events_path):
            if row.get("event_id") in original.event_ids:
                observations.append(row)

        from .decision_engine import run_platform_decision

        replayed = run_platform_decision(
            observations,
            endpoint_id=original.endpoint_id,
            run_id=original.run_id,
        )
        parity = {
            "policy_outcome": original.policy_outcome == replayed.policy_outcome,
            "state_path": original.state_path == replayed.state_path,
            "accepted_hypothesis": original.accepted_hypothesis == replayed.accepted_hypothesis,
        }
        return cls(original=original, replayed=replayed, parity=parity)

    @classmethod
    def replay_events(
        cls,
        events: list[NormalizedPlatformEvent],
        *,
        endpoint_id: str = "local",
        context: dict[str, Any] | None = None,
    ) -> PlatformDecisionRecord:
        """Replay from in-memory event list (tests / fixtures)."""
        from .decision_engine import run_platform_decision

        obs = [e.model_dump(mode="json") for e in events]
        return run_platform_decision(obs, endpoint_id=endpoint_id, context=context)

"""Public pipeline entry — re-exports unified run_pipeline."""

from __future__ import annotations

from src.platform.replay import PipelineResult, find_event, replay_all, run_pipeline

__all__ = ["PipelineResult", "find_event", "replay_all", "run_pipeline"]

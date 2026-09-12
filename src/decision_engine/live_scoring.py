"""Backward compatibility shim; canonical implementation: :mod:`src.hypothesis.live_scoring`."""

from __future__ import annotations

from ..hypothesis.live_scoring import LiveHypothesisScore, ranked_dicts, score_live_snapshot

__all__ = ["LiveHypothesisScore", "ranked_dicts", "score_live_snapshot"]

"""Append-only JSONL sinks for audit and outcome feedback (`logs/`)."""

from .audit import append_jsonl
from .feedback import FeedbackRecord, append_feedback

__all__ = ["FeedbackRecord", "append_feedback", "append_jsonl"]

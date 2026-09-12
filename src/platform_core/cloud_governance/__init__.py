"""Cloud governance module — mock-first Azure/GCP advisory recommendations."""

from __future__ import annotations

from .recommendations import (
    default_fixture_path,
    format_cloud_summary_markdown,
    load_cloud_recommendations,
    summarize_cloud_recommendations,
)

__all__ = [
    "default_fixture_path",
    "format_cloud_summary_markdown",
    "load_cloud_recommendations",
    "summarize_cloud_recommendations",
]

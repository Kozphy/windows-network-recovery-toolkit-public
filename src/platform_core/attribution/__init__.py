"""Proxy attribution — diagnostic-only registry/process correlation."""

from src.platform_core.attribution.classifier import classify_listener
from src.platform_core.attribution.collector import (
    attribution_to_evidence_records,
    collect_attribution,
    collect_proxy_state,
    resolve_listener_process,
)
from src.platform_core.attribution.models import (
    AttributionSnapshot,
    ListenerClassification,
    ProcessAttribution,
    ProxyStateSnapshot,
)
from src.platform_core.attribution.writer_engine import run_proxy_writer_attribution
from src.platform_core.attribution.writer_models import ProxyWriterAttributionResult

__all__ = [
    "AttributionSnapshot",
    "ListenerClassification",
    "ProcessAttribution",
    "ProxyStateSnapshot",
    "ProxyWriterAttributionResult",
    "attribution_to_evidence_records",
    "classify_listener",
    "collect_attribution",
    "collect_proxy_state",
    "resolve_listener_process",
    "run_proxy_writer_attribution",
]

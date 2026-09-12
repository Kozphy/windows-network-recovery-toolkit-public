"""OpenTelemetry tracing — optional, graceful degradation when OTel not installed."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_tracer: Any = None
_otel_available = False

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    _otel_available = True
except ImportError:
    trace = None  # type: ignore[assignment,misc]


def init_tracing(service_name: str = "endpoint-reliability-platform") -> bool:
    """Initialize OTel tracer if library is present."""
    global _tracer, _otel_available
    if not _otel_available or trace is None:
        return False
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(service_name)
    return True


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[None]:
    """Create a span or no-op when OTel unavailable."""
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as s:
        for k, v in attributes.items():
            s.set_attribute(k, str(v))
        yield


def get_trace_id() -> str | None:
    """Get trace id.
    
    Args:
        None.
    
    Returns:
        The str | None result produced by the operation.
    
    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    if not _otel_available or trace is None:
        return None
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx.trace_id:
        return format(ctx.trace_id, "032x")
    return None

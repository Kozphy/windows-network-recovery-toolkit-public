"""FastAPI routers for proxy incident dashboard."""

from src.api.routes_evidence_tree import router as evidence_tree_router
from src.api.routes_proxy_incidents import router as proxy_incidents_router

__all__ = ["proxy_incidents_router", "evidence_tree_router"]

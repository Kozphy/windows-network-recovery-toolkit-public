"""Demo RBAC for /v1 technology-risk API."""

from backend.auth.dependencies import get_v1_principal
from backend.auth.rbac import V1Principal, V1Role

__all__ = ["V1Principal", "V1Role", "get_v1_principal"]

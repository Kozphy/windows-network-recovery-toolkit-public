"""Decision Intelligence FastAPI module.

Exposes :data:`router` mounted at ``/decision-intelligence`` in :mod:`backend.main`.
"""

from .routes import router

__all__ = ["router"]

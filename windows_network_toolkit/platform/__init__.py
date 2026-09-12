"""Platform API, schemas, metrics, and dashboard for the ERP platform.

Module responsibility:
    Public surface of the ``platform`` sub-package.  Exports the Pydantic
    request/response schemas used by the FastAPI router and any external
    callers that construct or inspect API payloads.

System placement:
    The ``platform`` package is the outermost integration layer, connecting
    the ``evidence`` and ``decision`` sub-packages to the HTTP API (``api.py``)
    and the in-memory session store (``store.py``).  It also provides the
    policy evaluation and risk-scoring facades used by the pipeline.

Key invariants:
    * ``dry_run=True`` is the default on all request schemas that touch
      remediation; callers must explicitly opt into live execution.
    * All API responses include a ``dry_run`` flag so consumers can detect
      safe-mode vs. live-mode responses.
"""

from .schemas import DiagnoseRequest, HealthResponse, ReplayRequest

__all__ = ["DiagnoseRequest", "HealthResponse", "ReplayRequest"]

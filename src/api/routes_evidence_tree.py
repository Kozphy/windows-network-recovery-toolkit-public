"""Evidence tree API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from src.api import incident_store

router = APIRouter(prefix="/api/proxy", tags=["evidence-tree"])


@router.get("/incidents/{incident_id}/evidence-tree")
def get_evidence_tree(incident_id: str) -> dict:
    """Handle the GET request for get evidence tree.

    Args:
        incident_id: The incident id value supplied by the caller.

    Returns:
        Response payload serialized by FastAPI for the caller.

    Side effects:
        Reads request parameters and delegates response construction to backend services; mutating routes may write database rows, queue state, JSONL audit entries, or in-memory state.
    """
    bundle = incident_store.get_incident(incident_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return {"incident_id": incident_id, "evidence_tree": bundle.get("evidence_tree")}

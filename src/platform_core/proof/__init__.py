"""Direct vs proxied proof engine."""

from src.platform_core.proof.engine import classify_proof_outcome, run_proof_engine
from src.platform_core.proof.models import ProofObservation, ProofOutcome, ProofResult

__all__ = [
    "ProofObservation",
    "ProofOutcome",
    "ProofResult",
    "classify_proof_outcome",
    "run_proof_engine",
]

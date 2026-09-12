"""Causal verification steps (Proof Engine) — read-only probes by default.

Boundary: emits :class:`ProofResult` from registry/snapshot context and subprocess checks;
does not rank hypotheses or enforce ALLOW/PREVIEW/BLOCK (see :mod:`src.policy`).
"""

from __future__ import annotations

from .contracts import ProofCheck, ProofObservation, ProofResult, ProofStatus
from .proxy_https import LocalhostProxyHttpsProof, run_localhost_proxy_https_proof

__all__ = [
    "LocalhostProxyHttpsProof",
    "ProofCheck",
    "ProofObservation",
    "ProofResult",
    "ProofStatus",
    "run_localhost_proxy_https_proof",
]

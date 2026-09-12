"""Report signing placeholder — hash fingerprint for exports.

Module responsibility:
    Computes a deterministic SHA-256 content hash over a canonically serialised
    (sort_keys, no whitespace) report payload and returns it alongside a
    ``signature_status`` field.  The current implementation returns
    ``"unsigned"`` for ``signature_status``; the hash alone provides integrity
    verification.  Intended as the attachment point for a future HSM or
    asymmetric-key signing step without changing callers.

Typical usage:
    meta = sign_report_payload(report_dict)
    # {"signature_status": "unsigned", "content_hash_sha256": "<hex>"}

Limitations:
    - No asymmetric signing is performed; ``signature_status: unsigned`` must
      not be interpreted as a cryptographic attestation.
    - Input must be JSON-serialisable; non-serialisable values will raise
      ``TypeError`` from ``json.dumps``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sign_report_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Sign report payload.

    Args:
        payload: payload supplied by the caller.

    Returns:
        The computed `dict[str, Any]` value.

    Side effects:
        Reads data from the requested source.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {"signature_status": "unsigned", "content_hash_sha256": digest}

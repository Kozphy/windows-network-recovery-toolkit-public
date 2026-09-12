"""Release label embedded in diagnostics and audit rows.

Attributes:
    SCRIPT_VERSION: String label included in JSON outputs; informational only (not enforced as PEP 440).

Notes:
    Bump when changing report schema or operator-facing diagnostic semantics callers rely on.
"""

__all__ = ["SCRIPT_VERSION"]

SCRIPT_VERSION = "2.0.0"

"""Decision package interfaces for evidence-backed decision records.

Module responsibility:
    Expose package-level interfaces without performing runtime work.

System placement:
    Imported by platform modules that need the package namespace.

Key invariants:
    Importing this package must not collect evidence or mutate state.

Side effects:
    None.
"""

from .engine import build_decision

__all__ = ["build_decision"]

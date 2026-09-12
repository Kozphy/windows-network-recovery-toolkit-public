"""FastAPI SaaS demo backend: JWT auth, SQLite persistence, rules engine, Stripe billing.

Purpose:
    Package root for the optional hosted demo: authentication (:mod:`backend.auth`), SQLite
    (:mod:`backend.db`), diagnosis rules (:mod:`backend.engine`), and billing webhooks
    (:mod:`backend.billing`). Runtime wiring lives in :mod:`backend.main`.

Safety constraints:
    Routers enforce JWT where configured; remediation and subprocess delegation to ``src`` stay
    behind typed confirmations in :mod:`backend.live_observability` (no arbitrary shell from JSON bodies).

Notes:
    This package does not alter ``src`` CLI safety defaults; it composes them when operators use HTTP wrappers.
"""

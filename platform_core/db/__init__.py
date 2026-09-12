"""Optional PostgreSQL persistence for append-only platform stores."""

from platform_core.db.postgres import (
    append_decision_pg,
    append_event_pg,
    database_url,
    is_postgres_configured,
)

__all__ = [
    "append_decision_pg",
    "append_event_pg",
    "database_url",
    "is_postgres_configured",
]

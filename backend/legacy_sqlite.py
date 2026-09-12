"""SQLite persistence shared by ``backend.main`` demos (diagnosis, metering, billing metadata).

Module responsibility:
    Provides ``get_connection``, ``init_db`` (DDL sourced from adjacent ``schema.sql``), and
    CRUD helpers for users/orgs/projects, diagnosis history rows, coarse connection metrics,
    subscription placeholders, Stripe webhook mirrors, and month-scoped usage counters.

System placement:
    Sibling to ``backend.auth`` / ``backend.billing``; unrelated to append-only JSONL flows in
    ``platform_core.storage`` aside from coexistence inside the FastAPI host process.

Timezone assumptions:
    Timestamps originate from naive/aware datetime helpers annotated per function — prefer
    :func:`month_key` for UTC-aligned billing buckets when extending SQL.

Malformed data handling:
    Callers coerce JSON payloads before inserting; malformed rows surface as SQLite constraint
    errors bubbling to routers unless guarded.

Failure modes:
    ``init_db`` may raise ``sqlite3.Error`` when ``schema.sql`` cannot execute.

Audit Notes:
    Default DB path resolves to ``backend/toolkit.db`` — copy or embargo this file alongside JSONL
    exports when archiving demos; Stripe webhook duplication logic lives in routing code, but this
    module stores the transactional outcome rows.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).with_name("toolkit.db")
SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def _utc_now_iso() -> str:
    """Return the current instant in UTC as an ISO-8601 string.

    Returns:
        Timezone-aware ISO string suitable for SQLite text columns.

    Raises:
        None.
    """
    return datetime.now(UTC).isoformat()


def utc_now_iso_z() -> str:
    """Return UTC now as RFC 3339 with Zulu ``Z`` suffix (API-stable).

    Uses a timezone-aware clock; unlike naive ``utcnow().isoformat() + "Z"``, the
    instant is correct. ``Z`` replaces ``+00:00`` for clients that expect the legacy
    monitor response shape.
    """
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def get_connection() -> sqlite3.Connection:
    """Open the demo SQLite database at :data:`DB_PATH` with row dict access.

    Returns:
        Open ``sqlite3.Connection`` with ``row_factory`` set to ``sqlite3.Row``.

    Raises:
        sqlite3.Error: When the database file cannot be opened (permissions, path).

    Safety constraints:
        Persists to ``backend/toolkit.db`` by default; treat the file as sensitive (PII, usage) in exports.

    Side effects:
        May create the database file on first open.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Apply ``schema.sql`` to the SQLite database (idempotent DDL).

    Returns:
        None.

    Raises:
        sqlite3.Error: When ``schema.sql`` cannot be read or ``executescript`` fails.

    Side effects:
        Creates tables and indices; may fail mid-script if disk is full (operator should restore backup).

    Safety constraints:
        Destructive only insofar as DDL matches ``schema.sql``; intended for local demo bootstrap.
    """
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with get_connection() as conn:
        conn.executescript(schema)
        conn.commit()


def month_key(now: datetime | None = None) -> str:
    """Format a UTC month bucket ``YYYY-MM`` for usage counters.

    Args:
        now: Reference time; defaults to current UTC.

    Returns:
        Seven-character month key string.

    Raises:
        None.
    """
    dt = now or datetime.now(UTC)
    return dt.strftime("%Y-%m")


def ensure_user_org_project(user_id: str, email: str) -> None:
    """Ensure demo bootstrap rows exist: user, default org, project, free subscription.

    Args:
        user_id: Stable user identifier (JWT subject or synthetic).
        email: Email stored on insert/update.

    Returns:
        None.

    Raises:
        sqlite3.Error: On insert/update failure.

    Side effects:
        Commits inserts when the user lacks an organization.
    """
    with get_connection() as conn:
        existing = conn.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()
        if existing is None:
            conn.execute("INSERT INTO users (id, email) VALUES (?, ?)", (user_id, email))
        elif existing["email"] != email:
            conn.execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))

        org = conn.execute(
            "SELECT id FROM organizations WHERE owner_id = ? LIMIT 1",
            (user_id,),
        ).fetchone()
        if org is None:
            org_id = str(uuid.uuid4())
            proj_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO organizations (id, name, owner_id) VALUES (?, ?, ?)",
                (org_id, f"Org-{org_id[:8]}", user_id),
            )
            conn.execute(
                "INSERT INTO projects (id, org_id, name) VALUES (?, ?, ?)",
                (proj_id, org_id, "Default Project"),
            )
            conn.execute(
                "INSERT INTO subscriptions (org_id, plan, status) VALUES (?, ?, ?)",
                (org_id, "free", "active"),
            )
        conn.commit()


def get_project_for_user(user_id: str, requested_project_id: str | None) -> dict[str, Any] | None:
    """Resolve a project owned by ``user_id``, optionally pinned to a specific project id.

    Args:
        user_id: Owner user id.
        requested_project_id: When set, require that exact project id under the user’s orgs.

    Returns:
        Dict with ``project_id``, ``org_id``, and ``name``, or ``None`` when no row matches.

    Raises:
        None.

    Side effects:
        Read-only SQL.
    """
    with get_connection() as conn:
        if requested_project_id:
            row = conn.execute(
                """
                SELECT p.id AS project_id, p.org_id, p.name
                FROM projects p
                INNER JOIN organizations o ON o.id = p.org_id
                WHERE o.owner_id = ? AND p.id = ?
                """,
                (user_id, requested_project_id),
            ).fetchone()
            return dict(row) if row else None

        row = conn.execute(
            """
            SELECT p.id AS project_id, p.org_id, p.name
            FROM projects p
            INNER JOIN organizations o ON o.id = p.org_id
            WHERE o.owner_id = ?
            ORDER BY p.name
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def get_subscription(org_id: str) -> dict[str, Any]:
    """Load subscription metadata for an organization, or return a free-tier default.

    Args:
        org_id: Organization UUID string.

    Returns:
        Dict with at least ``plan``, ``status``, ``org_id``, and optional Stripe ids when present.

    Raises:
        None — missing rows synthesize ``plan=free``.

    Side effects:
        Read-only SQL.
    """
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT org_id, plan, status, stripe_customer_id, stripe_subscription_id
            FROM subscriptions WHERE org_id = ?
            """,
            (org_id,),
        ).fetchone()
    if not row:
        return {"plan": "free", "status": "active", "org_id": org_id}
    return dict(row)


def update_subscription(
    org_id: str,
    plan: str,
    status: str,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
) -> None:
    """Upsert subscription fields for billing demos (Stripe ids optional).

    Args:
        org_id: Organization id.
        plan: Plan label string stored verbatim.
        status: Subscription status string.
        stripe_customer_id: Optional Stripe customer id.
        stripe_subscription_id: Optional Stripe subscription id.

    Returns:
        None.

    Raises:
        sqlite3.Error: On constraint or I/O failure.

    Side effects:
        Commits one upsert to ``subscriptions``.
    """
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO subscriptions (org_id, plan, status, stripe_customer_id, stripe_subscription_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(org_id) DO UPDATE SET
                plan = excluded.plan,
                status = excluded.status,
                stripe_customer_id = COALESCE(
                    excluded.stripe_customer_id, subscriptions.stripe_customer_id),
                stripe_subscription_id = COALESCE(
                    excluded.stripe_subscription_id, subscriptions.stripe_subscription_id)
            """,
            (org_id, plan, status, stripe_customer_id, stripe_subscription_id),
        )
        conn.commit()


def get_usage(org_id: str, month: str) -> dict[str, Any]:
    """Return diagnosis usage count for an org/month bucket.

    Args:
        org_id: Organization id.
        month: ``YYYY-MM`` key matching :func:`month_key`.

    Returns:
        Dict with ``org_id``, ``month``, and ``diagnosis_count`` (zero when absent).

    Raises:
        None.

    Side effects:
        Read-only SQL.
    """
    with get_connection() as conn:
        row = conn.execute(
            "SELECT org_id, month, diagnosis_count FROM usage WHERE org_id = ? AND month = ?",
            (org_id, month),
        ).fetchone()
    if row:
        return {
            "org_id": row["org_id"],
            "month": row["month"],
            "diagnosis_count": int(row["diagnosis_count"]),
        }
    return {"org_id": org_id, "month": month, "diagnosis_count": 0}


def try_increment_usage_with_limit(org_id: str, limit: int, month: str) -> int | None:
    """Atomically increment monthly diagnosis usage when under plan limit.

    Args:
        org_id: Organization id.
        limit: Max diagnoses for the month; ``-1`` means unlimited.
        month: ``YYYY-MM`` bucket.

    Returns:
        New ``diagnosis_count`` after increment, or ``None`` when already at limit (no increment).

    Raises:
        sqlite3.Error: On transaction failure.

    Side effects:
        Uses ``BEGIN IMMEDIATE`` and commits or rolls back.
    """
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT diagnosis_count FROM usage WHERE org_id = ? AND month = ?",
            (org_id, month),
        ).fetchone()
        current = int(row["diagnosis_count"]) if row else 0
        if limit != -1 and current >= limit:
            conn.rollback()
            return None
        conn.execute(
            """
            INSERT INTO usage (org_id, month, diagnosis_count)
            VALUES (?, ?, 1)
            ON CONFLICT(org_id, month) DO UPDATE SET
                diagnosis_count = diagnosis_count + 1
            """,
            (org_id, month),
        )
        row2 = conn.execute(
            "SELECT diagnosis_count FROM usage WHERE org_id = ? AND month = ?",
            (org_id, month),
        ).fetchone()
        conn.commit()
        return int(row2["diagnosis_count"]) if row2 else None


def insert_diagnosis(*, project_id: str, input_data: dict[str, Any], result: dict[str, Any]) -> int:
    """Persist one diagnosis request/response pair as JSON blobs.

    Args:
        project_id: Owning project UUID.
        input_data: Request payload dict (serialized with ``json.dumps``).
        result: Response payload dict.

    Returns:
        SQLite ``lastrowid`` for the inserted ``diagnosis_logs`` row.

    Raises:
        sqlite3.Error: On insert failure.

    Side effects:
        Commits one insert with UTC ``created_at``.
    """
    created = datetime.now(UTC).isoformat()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO diagnosis_logs (project_id, input_data, result, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (project_id, json.dumps(input_data), json.dumps(result), created),
        )
        conn.commit()
        return int(cur.lastrowid)


def insert_metric(*, project_id: str, time_wait: int, established: int) -> tuple[int, str]:
    """Record coarse TCP connection metrics for a project.

    Args:
        project_id: Owning project UUID.
        time_wait: Count or gauge stored as integer (caller's semantics).
        established: Count or gauge stored as integer.

    Returns:
        ``(lastrowid, created_at)`` where ``created_at`` is RFC 3339 UTC with ``Z`` suffix.

    Raises:
        sqlite3.Error: On insert failure.

    Side effects:
        Commits one insert.
    """
    created = utc_now_iso_z()
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO connection_metrics (project_id, time_wait, established, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (project_id, time_wait, established, created),
        )
        conn.commit()
        return int(cur.lastrowid), created


def get_recent_metrics(project_id: str, limit: int) -> list[dict[str, Any]]:
    """Return recent connection metric rows for a project (newest first).

    Args:
        project_id: Project UUID.
        limit: Desired row cap (clamped to 1..100).

    Returns:
        List of dicts with ``time_wait``, ``established``, and ``timestamp`` keys.

    Raises:
        None.

    Side effects:
        Read-only SQL.
    """
    safe = max(1, min(limit, 100))
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT time_wait, established, created_at
            FROM connection_metrics
            WHERE project_id = ?
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (project_id, safe),
        ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        item["timestamp"] = item.pop("created_at")
        out.append(item)
    return out


def get_history(
    org_id: str,
    project_id: str | None,
    limit: int,
) -> dict[str, Any]:
    """Fetch recent diagnosis logs and connection metrics for an organization.

    Args:
        org_id: Organization UUID filtering joined projects.
        project_id: Optional project scope; when omitted, uses all projects in the org.
        limit: Per-stream cap for diagnoses and metrics (clamped to 1..500 each).

    Returns:
        Dict with ``diagnoses`` and ``metrics`` lists (each sorted by id desc within limit).

    Raises:
        json.JSONDecodeError: If stored JSON blobs are corrupted (should not occur for normal inserts).

    Side effects:
        Read-only SQL; parses JSON columns into Python dicts.
    """
    safe = max(1, min(limit, 500))

    diag_sql = """
        SELECT dl.id, dl.project_id, dl.input_data, dl.result, dl.created_at
        FROM diagnosis_logs dl
        INNER JOIN projects p ON p.id = dl.project_id
        WHERE p.org_id = ?
    """
    met_sql = """
        SELECT cm.id, cm.project_id, cm.time_wait, cm.established, cm.created_at
        FROM connection_metrics cm
        INNER JOIN projects p ON p.id = cm.project_id
        WHERE p.org_id = ?
    """
    diag_params: list[Any] = [org_id]
    met_params: list[Any] = [org_id]
    if project_id:
        diag_sql += " AND dl.project_id = ?"
        met_sql += " AND cm.project_id = ?"
        diag_params.append(project_id)
        met_params.append(project_id)

    diag_sql += " ORDER BY dl.id DESC LIMIT ?"
    met_sql += " ORDER BY cm.id DESC LIMIT ?"
    diag_params.append(safe)
    met_params.append(safe)

    with get_connection() as conn:
        drows = conn.execute(diag_sql, diag_params).fetchall()
        mrows = conn.execute(met_sql, met_params).fetchall()

    diagnoses: list[dict[str, Any]] = []
    for r in drows:
        diagnoses.append(
            {
                "id": r["id"],
                "project_id": r["project_id"],
                "input": json.loads(r["input_data"]),
                "result": json.loads(r["result"]),
                "created_at": r["created_at"],
            }
        )
    metrics_out: list[dict[str, Any]] = []
    for r in mrows:
        metrics_out.append(
            {
                "id": r["id"],
                "project_id": r["project_id"],
                "time_wait": r["time_wait"],
                "established": r["established"],
                "timestamp": r["created_at"],
            }
        )

    return {"diagnoses": diagnoses, "metrics": metrics_out}

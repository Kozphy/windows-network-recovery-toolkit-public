"""Persistence models for the first product-control-plane vertical slice.

Module responsibility:
    SQLModel tables for organizations, enrollment tokens, agent credentials,
    heartbeats, and the classification outbox. Additive to the existing
    technology-risk schema.

System placement:
    Imported by ``backend.product_v1_routes`` and ``backend.product_outbox``.
    Metadata must be imported before ``init_trisk_schema`` / ``create_all`` so
    SQLite demos create these tables.

Key invariants:
    - Secrets are never stored in plaintext; only SHA-256 hashes (with a
      deployment pepper applied in the service layer) are persisted.
    - Timestamps default via ``utc_now`` (timezone-aware UTC).
    - Heartbeat client ids are unique per ``endpoint_id``, not globally.

Side effects:
    None at import beyond SQLAlchemy table registration on the shared metadata.

Failure modes:
    Unique constraint violations surface as IntegrityError at commit time
    (handled in enrollment / heartbeat routes).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import UniqueConstraint
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    """Return the current UTC time for model default factories.

    Returns:
        Timezone-aware datetime in UTC.
    """
    return datetime.now(UTC)


class ProductOrganization(SQLModel, table=True):
    """Tenant organization row keyed by authenticated principal tenant id.

    ``organization_id`` is assigned from the V1 principal, not from request
    bodies, so clients cannot override tenant scope at create time.
    """

    __tablename__ = "product_organizations"

    id: int | None = Field(default=None, primary_key=True)
    organization_id: str = Field(unique=True, index=True, max_length=64)
    display_name: str = Field(max_length=256)
    created_by_actor: str = Field(max_length=128)
    created_at: datetime = Field(default_factory=utc_now)


class EnrollmentToken(SQLModel, table=True):
    """Bootstrap token hash for agent enrollment.

    Stores ``token_hash`` only. Plaintext is returned once at issuance.
    Default ``max_uses=1`` with ``consumed_at`` supports single-use enrollment.
    """

    __tablename__ = "product_enrollment_tokens"

    id: int | None = Field(default=None, primary_key=True)
    token_id: str = Field(unique=True, index=True, max_length=64)
    organization_id: str = Field(index=True, max_length=64)
    token_hash: str = Field(unique=True, index=True, max_length=64)
    expires_at: datetime
    revoked_at: datetime | None = Field(default=None)
    consumed_at: datetime | None = Field(default=None)
    max_uses: int = Field(default=1, ge=1)
    use_count: int = Field(default=0, ge=0)
    created_by_actor: str = Field(max_length=128)
    created_at: datetime = Field(default_factory=utc_now)


class AgentCredential(SQLModel, table=True):
    """Durable agent secret hash bound to one organization + endpoint.

    Rotation updates ``secret_hash`` and ``rotated_at`` in place (same
    ``endpoint_id``). Revocation sets ``revoked_at``; reissue clears it and
    issues a new secret hash.
    """

    __tablename__ = "product_agent_credentials"
    __table_args__ = (
        UniqueConstraint("organization_id", "endpoint_id", name="uq_product_agent_org_endpoint"),
    )

    id: int | None = Field(default=None, primary_key=True)
    credential_id: str = Field(unique=True, index=True, max_length=64)
    organization_id: str = Field(index=True, max_length=64)
    endpoint_id: str = Field(index=True, max_length=128)
    secret_hash: str = Field(unique=True, index=True, max_length=64)
    revoked_at: datetime | None = Field(default=None)
    rotated_at: datetime | None = Field(default=None)
    last_used_at: datetime | None = Field(default=None)
    created_at: datetime = Field(default_factory=utc_now)


class AgentHeartbeat(SQLModel, table=True):
    """Agent liveness observation; not an endpoint health or classification claim.

    Client-controlled ``heartbeat_id`` values are unique per ``endpoint_id``.
    A global unique constraint would reject a second endpoint reusing the same
    id after the route's (heartbeat_id, endpoint_id) duplicate check allowed it.
    """

    __tablename__ = "product_agent_heartbeats"
    __table_args__ = (
        UniqueConstraint(
            "endpoint_id",
            "heartbeat_id",
            name="uq_product_heartbeat_endpoint_id",
        ),
    )

    id: int | None = Field(default=None, primary_key=True)
    heartbeat_id: str = Field(index=True, max_length=64)
    organization_id: str = Field(index=True, max_length=64)
    endpoint_id: str = Field(index=True, max_length=128)
    agent_version: str = Field(default="unknown", max_length=64)
    os_name: str = Field(default="Windows", max_length=128)
    os_version: str | None = Field(default=None, max_length=128)
    status: str = Field(default="ONLINE_UNASSESSED", max_length=32)
    observed_at: datetime = Field(default_factory=utc_now, index=True)
    received_at: datetime = Field(default_factory=utc_now)


class ClassificationOutbox(SQLModel, table=True):
    """Durable handoff from evidence commit to classification enqueue.

    Evidence and this row commit together. Queue dispatch happens after commit so
    workers never see an unpublished ``event_id``; failed dispatch leaves a
    pending outbox row that retries can re-drive.

    Status values observed in code paths: ``pending``, ``dispatched``.
    ``attempts`` increments on each dispatch try; ``last_error`` is truncated in
    the dispatcher (max 512 chars on the column).
    """

    __tablename__ = "product_classification_outbox"
    __table_args__ = (UniqueConstraint("event_id", name="uq_product_classification_outbox_event"),)

    id: int | None = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, max_length=64)
    idempotency_key: str = Field(index=True, max_length=64)
    organization_id: str = Field(index=True, max_length=64)
    endpoint_id: str = Field(index=True, max_length=128)
    status: str = Field(default="pending", max_length=32)
    attempts: int = Field(default=0, ge=0)
    last_error: str | None = Field(default=None, max_length=512)
    job_id: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    dispatched_at: datetime | None = Field(default=None)

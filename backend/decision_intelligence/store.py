"""Decision Intelligence persistence — PostgreSQL when configured, else JSONL.

System placement:
    - Used by :mod:`backend.decision_intelligence.routes` and :mod:`service`.
    - Schema DDL: ``platform_core/db/decision_intelligence_schema.sql``.

Backend selection:
    - :func:`get_store` prefers PostgreSQL when :func:`platform_core.db.postgres.is_postgres_configured`.
    - Falls back to :class:`JsonlDecisionIntelligenceStore` on connection failure.

Idempotency:
    - PostgreSQL inserts use ``ON CONFLICT DO NOTHING`` on primary keys.
    - JSONL appends are always additive (duplicates possible if callers reuse IDs).

Side effects:
    - Creates directories and append-only ``*.jsonl`` files (JSONL mode).
    - Commits SQL transactions (PostgreSQL mode).

Audit Notes:
    - JSONL mode is local-first; protect ``PLATFORM_DATA_DIR`` like any audit log.
    - ``reset_store`` clears the process singleton (tests only).
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from platform_core.db.postgres import database_url, is_postgres_configured
from platform_core.settings import get_settings

from .models import (
    DecisionCreate,
    DecisionFilters,
    DecisionRecord,
    EventCreate,
    EventFilters,
    EventRecord,
    EvidenceCreate,
    EvidenceFilters,
    EvidenceRecord,
    OutcomeCreate,
    OutcomeFilters,
    OutcomeRecord,
    PaginatedResponse,
)


def _paginate(items: list[Any], page: int, page_size: int) -> PaginatedResponse[Any]:
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]
    return PaginatedResponse(
        items=page_items,
        page=page,
        page_size=page_size,
        total=total,
        has_more=end < total,
    )


class DecisionIntelligenceStore(ABC):
    """Represent decision intelligence store data used by the toolkit.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    @abstractmethod
    def backend_name(self) -> str:
        """Backend name.

        Args:
            None.

        Returns:
            The str result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

    @abstractmethod
    def counts(self) -> dict[str, int]:
        """Counts.

        Args:
            None.

        Returns:
            The dict[str, int] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

    @abstractmethod
    def create_event(self, row: EventCreate) -> EventRecord:
        """Create event.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The EventRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

    @abstractmethod
    def list_events(
        self, filters: EventFilters, page: int, page_size: int
    ) -> PaginatedResponse[EventRecord]:
        """List events.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[EventRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

    @abstractmethod
    def create_evidence(self, row: EvidenceCreate) -> EvidenceRecord:
        """Create evidence.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The EvidenceRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

    @abstractmethod
    def list_evidence(
        self, filters: EvidenceFilters, page: int, page_size: int
    ) -> PaginatedResponse[EvidenceRecord]:
        """List evidence.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[EvidenceRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

    @abstractmethod
    def create_decision(self, row: DecisionCreate) -> DecisionRecord:
        """Create decision.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The DecisionRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        ...

    @abstractmethod
    def list_decisions(
        self, filters: DecisionFilters, page: int, page_size: int
    ) -> PaginatedResponse[DecisionRecord]:
        """List decisions.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[DecisionRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        ...

    @abstractmethod
    def create_outcome(self, row: OutcomeCreate) -> OutcomeRecord:
        """Create outcome.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The OutcomeRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

    @abstractmethod
    def list_outcomes(
        self, filters: OutcomeFilters, page: int, page_size: int
    ) -> PaginatedResponse[OutcomeRecord]:
        """List outcomes.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[OutcomeRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...

    @abstractmethod
    def list_all_outcomes(self) -> list[OutcomeRecord]:
        """List all outcomes.

        Args:
            None.

        Returns:
            The list[OutcomeRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        ...


class JsonlDecisionIntelligenceStore(DecisionIntelligenceStore):
    """Local-first JSONL store under ``PLATFORM_DATA_DIR/decision_intelligence/``."""

    def __init__(self, root: Path | None = None) -> None:
        """Initialize the object with caller supplied state.

        Args:
            root: Repository root used to resolve fixtures, reports, or local state.

        Returns:
            None.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        base = root or get_settings().platform_data_dir / "decision_intelligence"
        base.mkdir(parents=True, exist_ok=True)
        self._root = base
        self._events = base / "events.jsonl"
        self._evidence = base / "evidence.jsonl"
        self._decisions = base / "decisions.jsonl"
        self._outcomes = base / "outcomes.jsonl"

    def backend_name(self) -> str:
        """Backend name.

        Args:
            None.

        Returns:
            The str result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return "jsonl"

    def _append(self, path: Path, row: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _read_all(self, path: Path) -> list[dict[str, Any]]:
        if not path.is_file():
            return []
        rows: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        return rows

    def counts(self) -> dict[str, int]:
        """Counts.

        Args:
            None.

        Returns:
            The dict[str, int] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "events": len(self._read_all(self._events)),
            "evidence": len(self._read_all(self._evidence)),
            "decisions": len(self._read_all(self._decisions)),
            "outcomes": len(self._read_all(self._outcomes)),
        }

    def create_event(self, row: EventCreate) -> EventRecord:
        """Create event.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The EventRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        payload = row.model_dump(mode="json")
        self._append(self._events, payload)
        return EventRecord.model_validate(payload)

    def list_events(
        self, filters: EventFilters, page: int, page_size: int
    ) -> PaginatedResponse[EventRecord]:
        """List events.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[EventRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        rows = [EventRecord.model_validate(r) for r in self._read_all(self._events)]
        rows = _filter_events(rows, filters)
        rows.sort(key=lambda r: (r.timestamp_utc, r.event_id), reverse=True)
        return _paginate(rows, page, page_size)

    def create_evidence(self, row: EvidenceCreate) -> EvidenceRecord:
        """Create evidence.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The EvidenceRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        payload = row.model_dump(mode="json")
        self._append(self._evidence, payload)
        return EvidenceRecord.model_validate(payload)

    def list_evidence(
        self, filters: EvidenceFilters, page: int, page_size: int
    ) -> PaginatedResponse[EvidenceRecord]:
        """List evidence.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[EvidenceRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        rows = [EvidenceRecord.model_validate(r) for r in self._read_all(self._evidence)]
        rows = _filter_evidence(rows, filters)
        rows.sort(key=lambda r: r.evidence_id)
        return _paginate(rows, page, page_size)

    def create_decision(self, row: DecisionCreate) -> DecisionRecord:
        """Create decision.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The DecisionRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        payload = row.model_dump(mode="json")
        self._append(self._decisions, payload)
        return DecisionRecord.model_validate(payload)

    def list_decisions(
        self, filters: DecisionFilters, page: int, page_size: int
    ) -> PaginatedResponse[DecisionRecord]:
        """List decisions.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[DecisionRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        rows = [DecisionRecord.model_validate(r) for r in self._read_all(self._decisions)]
        rows = _filter_decisions(rows, filters)
        rows.sort(key=lambda r: (r.timestamp_utc, r.decision_id), reverse=True)
        return _paginate(rows, page, page_size)

    def create_outcome(self, row: OutcomeCreate) -> OutcomeRecord:
        """Create outcome.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The OutcomeRecord result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        payload = row.model_dump(mode="json")
        self._append(self._outcomes, payload)
        return OutcomeRecord.model_validate(payload)

    def list_outcomes(
        self, filters: OutcomeFilters, page: int, page_size: int
    ) -> PaginatedResponse[OutcomeRecord]:
        """List outcomes.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[OutcomeRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        rows = [OutcomeRecord.model_validate(r) for r in self._read_all(self._outcomes)]
        rows = _filter_outcomes(rows, filters)
        rows.sort(key=lambda r: (r.recorded_at_utc, r.outcome_id), reverse=True)
        return _paginate(rows, page, page_size)

    def list_all_outcomes(self) -> list[OutcomeRecord]:
        """List all outcomes.

        Args:
            None.

        Returns:
            The list[OutcomeRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return [OutcomeRecord.model_validate(r) for r in self._read_all(self._outcomes)]


class PostgresDecisionIntelligenceStore(DecisionIntelligenceStore):
    """PostgreSQL-backed store using ``di_*`` tables."""

    def __init__(self, url: str | None = None) -> None:
        """Initialize the object with caller supplied state.

        Args:
            url: The url value supplied by the caller.

        Returns:
            None.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        self._url = url or database_url()
        if not self._url:
            raise ValueError("postgres url required")

    def _connect(self):  # type: ignore[no-untyped-def]
        import psycopg2  # type: ignore[import-untyped]

        return psycopg2.connect(self._url)

    def backend_name(self) -> str:
        """Backend name.

        Args:
            None.

        Returns:
            The str result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return "postgresql"

    def counts(self) -> dict[str, int]:
        """Counts.

        Args:
            None.

        Returns:
            The dict[str, int] result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                out: dict[str, int] = {}
                for table, key in (
                    ("di_events", "events"),
                    ("di_evidence", "evidence"),
                    ("di_decisions", "decisions"),
                    ("di_outcomes", "outcomes"),
                ):
                    cur.execute(f"SELECT COUNT(*) FROM {table}")
                    out[key] = int(cur.fetchone()[0])
        return out

    def create_event(self, row: EventCreate) -> EventRecord:
        """Create event.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The EventRecord result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO di_events (event_id, domain, title, category, timestamp_utc, payload)
                    VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                    ON CONFLICT (event_id) DO NOTHING
                    RETURNING created_at
                    """,
                    (
                        row.event_id,
                        row.domain,
                        row.title,
                        row.category,
                        row.timestamp_utc,
                        json.dumps(row.payload),
                    ),
                )
                created = cur.fetchone()
            conn.commit()
        record = EventRecord.model_validate(row.model_dump())
        if created:
            record.created_at = created[0].isoformat()
        return record

    def list_events(
        self, filters: EventFilters, page: int, page_size: int
    ) -> PaginatedResponse[EventRecord]:
        """List events.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[EventRecord] result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if filters.domain:
            clauses.append("domain = %s")
            params.append(filters.domain)
        if filters.category:
            clauses.append("category = %s")
            params.append(filters.category)
        if filters.event_id:
            clauses.append("event_id = %s")
            params.append(filters.event_id)
        if filters.since:
            clauses.append("timestamp_utc >= %s")
            params.append(filters.since)
        if filters.until:
            clauses.append("timestamp_utc <= %s")
            params.append(filters.until)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        offset = (page - 1) * page_size
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM di_events {where}", params)
                total = int(cur.fetchone()[0])
                cur.execute(
                    f"""
                    SELECT event_id, domain, title, category, timestamp_utc, payload, created_at
                    FROM di_events {where}
                    ORDER BY timestamp_utc DESC, event_id ASC
                    LIMIT %s OFFSET %s
                    """,
                    [*params, page_size, offset],
                )
                rows = cur.fetchall()
        items = [
            EventRecord(
                event_id=r[0],
                domain=r[1],
                title=r[2],
                category=r[3],
                timestamp_utc=r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
                payload=r[5] if isinstance(r[5], dict) else json.loads(r[5] or "{}"),
                created_at=r[6].isoformat() if r[6] else None,
            )
            for r in rows
        ]
        return PaginatedResponse(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
            has_more=offset + len(items) < total,
        )

    def create_evidence(self, row: EvidenceCreate) -> EvidenceRecord:
        """Create evidence.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The EvidenceRecord result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO di_evidence
                    (evidence_id, event_id, decision_id, label, kind, weight,
                     supports_decision, detail, payload)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                    ON CONFLICT (evidence_id) DO NOTHING
                    RETURNING created_at
                    """,
                    (
                        row.evidence_id,
                        row.event_id,
                        row.decision_id,
                        row.label,
                        row.kind,
                        row.weight,
                        row.supports_decision,
                        row.detail,
                        json.dumps(row.payload),
                    ),
                )
                created = cur.fetchone()
            conn.commit()
        record = EvidenceRecord.model_validate(row.model_dump())
        if created:
            record.created_at = created[0].isoformat()
        return record

    def list_evidence(
        self, filters: EvidenceFilters, page: int, page_size: int
    ) -> PaginatedResponse[EvidenceRecord]:
        """List evidence.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[EvidenceRecord] result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if filters.event_id:
            clauses.append("event_id = %s")
            params.append(filters.event_id)
        if filters.decision_id:
            clauses.append("decision_id = %s")
            params.append(filters.decision_id)
        if filters.kind:
            clauses.append("kind = %s")
            params.append(filters.kind)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        offset = (page - 1) * page_size
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM di_evidence {where}", params)
                total = int(cur.fetchone()[0])
                cur.execute(
                    f"""
                    SELECT evidence_id, event_id, decision_id, label, kind, weight,
                           supports_decision, detail, payload, created_at
                    FROM di_evidence {where}
                    ORDER BY evidence_id ASC
                    LIMIT %s OFFSET %s
                    """,
                    [*params, page_size, offset],
                )
                rows = cur.fetchall()
        items = [
            EvidenceRecord(
                evidence_id=r[0],
                event_id=r[1],
                decision_id=r[2],
                label=r[3],
                kind=r[4],
                weight=float(r[5]),
                supports_decision=r[6],
                detail=r[7] or "",
                payload=r[8] if isinstance(r[8], dict) else json.loads(r[8] or "{}"),
                created_at=r[9].isoformat() if r[9] else None,
            )
            for r in rows
        ]
        return PaginatedResponse(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
            has_more=offset + len(items) < total,
        )

    def create_decision(self, row: DecisionCreate) -> DecisionRecord:
        """Create decision.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The DecisionRecord result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO di_decisions
                    (decision_id, domain, title, confidence, risk_score, policy_status,
                     payload, content_digest, timestamp_utc)
                    VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
                    ON CONFLICT (decision_id) DO NOTHING
                    RETURNING created_at
                    """,
                    (
                        row.decision_id,
                        row.domain,
                        row.title,
                        row.confidence,
                        row.risk_score,
                        row.policy_status,
                        json.dumps(row.payload),
                        row.content_digest,
                        row.timestamp_utc,
                    ),
                )
                created = cur.fetchone()
            conn.commit()
        record = DecisionRecord.model_validate(row.model_dump())
        if created:
            record.created_at = created[0].isoformat()
        return record

    def list_decisions(
        self, filters: DecisionFilters, page: int, page_size: int
    ) -> PaginatedResponse[DecisionRecord]:
        """List decisions.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[DecisionRecord] result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.

        Audit Notes:
            Preserves observation, policy, and audit boundaries established by the caller.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if filters.domain:
            clauses.append("domain = %s")
            params.append(filters.domain)
        if filters.decision_id:
            clauses.append("decision_id = %s")
            params.append(filters.decision_id)
        if filters.policy_status:
            clauses.append("policy_status = %s")
            params.append(filters.policy_status)
        if filters.min_confidence is not None:
            clauses.append("confidence >= %s")
            params.append(filters.min_confidence)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        offset = (page - 1) * page_size
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM di_decisions {where}", params)
                total = int(cur.fetchone()[0])
                cur.execute(
                    f"""
                    SELECT decision_id, domain, title, confidence, risk_score, policy_status,
                           payload, content_digest, timestamp_utc, created_at
                    FROM di_decisions {where}
                    ORDER BY timestamp_utc DESC, decision_id ASC
                    LIMIT %s OFFSET %s
                    """,
                    [*params, page_size, offset],
                )
                rows = cur.fetchall()
        items = [
            DecisionRecord(
                decision_id=r[0],
                domain=r[1],
                title=r[2],
                confidence=float(r[3]),
                risk_score=float(r[4]),
                policy_status=r[5],
                payload=r[6] if isinstance(r[6], dict) else json.loads(r[6] or "{}"),
                content_digest=r[7] or "",
                timestamp_utc=r[8].isoformat() if hasattr(r[8], "isoformat") else str(r[8]),
                created_at=r[9].isoformat() if r[9] else None,
            )
            for r in rows
        ]
        return PaginatedResponse(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
            has_more=offset + len(items) < total,
        )

    def create_outcome(self, row: OutcomeCreate) -> OutcomeRecord:
        """Create outcome.

        Args:
            row: The row value supplied by the caller.

        Returns:
            The OutcomeRecord result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO di_outcomes
                    (outcome_id, decision_id, outcome, success, predicted_success,
                     cost, time_to_resolution, notes, recorded_at_utc)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (outcome_id) DO NOTHING
                    RETURNING created_at
                    """,
                    (
                        row.outcome_id,
                        row.decision_id,
                        row.outcome,
                        row.success,
                        row.predicted_success,
                        row.cost,
                        row.time_to_resolution,
                        row.notes,
                        row.recorded_at_utc,
                    ),
                )
                created = cur.fetchone()
            conn.commit()
        record = OutcomeRecord.model_validate(row.model_dump())
        if created:
            record.created_at = created[0].isoformat()
        return record

    def list_outcomes(
        self, filters: OutcomeFilters, page: int, page_size: int
    ) -> PaginatedResponse[OutcomeRecord]:
        """List outcomes.

        Args:
            filters: The filters value supplied by the caller.
            page: The page value supplied by the caller.
            page_size: The page size value supplied by the caller.

        Returns:
            The PaginatedResponse[OutcomeRecord] result produced by the operation.

        Side effects:
            May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if filters.decision_id:
            clauses.append("decision_id = %s")
            params.append(filters.decision_id)
        if filters.success is not None:
            clauses.append("success = %s")
            params.append(filters.success)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        offset = (page - 1) * page_size
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT COUNT(*) FROM di_outcomes {where}", params)
                total = int(cur.fetchone()[0])
                cur.execute(
                    f"""
                    SELECT outcome_id, decision_id, outcome, success, predicted_success,
                           cost, time_to_resolution, notes, recorded_at_utc, created_at
                    FROM di_outcomes {where}
                    ORDER BY recorded_at_utc DESC, outcome_id ASC
                    LIMIT %s OFFSET %s
                    """,
                    [*params, page_size, offset],
                )
                rows = cur.fetchall()
        items = [
            OutcomeRecord(
                outcome_id=r[0],
                decision_id=r[1],
                outcome=r[2],
                success=bool(r[3]),
                predicted_success=bool(r[4]),
                cost=float(r[5]),
                time_to_resolution=float(r[6]),
                notes=r[7] or "",
                recorded_at_utc=r[8].isoformat() if hasattr(r[8], "isoformat") else str(r[8]),
                created_at=r[9].isoformat() if r[9] else None,
            )
            for r in rows
        ]
        return PaginatedResponse(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
            has_more=offset + len(items) < total,
        )

    def list_all_outcomes(self) -> list[OutcomeRecord]:
        """List all outcomes.

        Args:
            None.

        Returns:
            The list[OutcomeRecord] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        page = self.list_outcomes(OutcomeFilters(), page=1, page_size=10_000)
        return list(page.items)


def _filter_events(rows: list[EventRecord], filters: EventFilters) -> list[EventRecord]:
    out = rows
    if filters.domain:
        out = [r for r in out if r.domain == filters.domain]
    if filters.category:
        out = [r for r in out if r.category == filters.category]
    if filters.event_id:
        out = [r for r in out if r.event_id == filters.event_id]
    if filters.since:
        out = [r for r in out if r.timestamp_utc >= filters.since]
    if filters.until:
        out = [r for r in out if r.timestamp_utc <= filters.until]
    return out


def _filter_evidence(rows: list[EvidenceRecord], filters: EvidenceFilters) -> list[EvidenceRecord]:
    out = rows
    if filters.event_id:
        out = [r for r in out if r.event_id == filters.event_id]
    if filters.decision_id:
        out = [r for r in out if r.decision_id == filters.decision_id]
    if filters.kind:
        out = [r for r in out if r.kind == filters.kind]
    return out


def _filter_decisions(rows: list[DecisionRecord], filters: DecisionFilters) -> list[DecisionRecord]:
    out = rows
    if filters.domain:
        out = [r for r in out if r.domain == filters.domain]
    if filters.decision_id:
        out = [r for r in out if r.decision_id == filters.decision_id]
    if filters.policy_status:
        out = [r for r in out if r.policy_status == filters.policy_status]
    if filters.min_confidence is not None:
        out = [r for r in out if r.confidence >= filters.min_confidence]
    return out


def _filter_outcomes(rows: list[OutcomeRecord], filters: OutcomeFilters) -> list[OutcomeRecord]:
    out = rows
    if filters.decision_id:
        out = [r for r in out if r.decision_id == filters.decision_id]
    if filters.success is not None:
        out = [r for r in out if r.success == filters.success]
    return out


_store: DecisionIntelligenceStore | None = None


def get_store() -> DecisionIntelligenceStore:
    """Return the process-wide store singleton (PostgreSQL or JSONL).

    Returns:
        Cached :class:`DecisionIntelligenceStore` instance.

    Notes:
        First call probes PostgreSQL; silently falls back to JSONL on error.
    """
    global _store
    if _store is not None:
        return _store
    if is_postgres_configured():
        try:
            _store = PostgresDecisionIntelligenceStore()
            return _store
        except Exception:
            pass
    _store = JsonlDecisionIntelligenceStore()
    return _store


def reset_store() -> None:
    """Clear the store singleton (test harness only)."""
    global _store
    _store = None


def init_schema_if_postgres() -> bool:
    """Apply decision intelligence DDL when PostgreSQL is configured.

    Returns:
        True when schema SQL was applied successfully; False when Postgres is
        unavailable, schema file is missing, or apply fails.
    """
    if not is_postgres_configured():
        return False
    schema_path = (
        Path(__file__).resolve().parents[2]
        / "platform_core"
        / "db"
        / "decision_intelligence_schema.sql"
    )
    if not schema_path.is_file():
        return False
    try:
        import psycopg2  # type: ignore[import-untyped]

        conn = psycopg2.connect(database_url())
        try:
            with conn.cursor() as cur:
                cur.execute(schema_path.read_text(encoding="utf-8"))
            conn.commit()
            return True
        finally:
            conn.close()
    except Exception:
        return False

"""Technology-risk persistence — SQLModel engine and session factory."""

from __future__ import annotations

import os
from collections.abc import Generator
from contextlib import contextmanager

from sqlmodel import Session, SQLModel, create_engine

_engine = None
_engine_url: str | None = None


def get_database_url() -> str:
    """Get database url.

    Args:
        None.

    Returns:
        The str result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    return os.getenv(
        "TRISK_DATABASE_URL",
        os.getenv(
            "DATABASE_URL",
            "sqlite:///./trisk_local.db",
        ),
    )


def reset_engine() -> None:
    """Clear cached engine (tests when TRISK_DATABASE_URL changes)."""
    global _engine, _engine_url
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _engine_url = None


def get_engine():
    """Get engine.

    Args:
        None.

    Returns:
        The computed result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    global _engine, _engine_url
    url = get_database_url()
    if _engine is None or _engine_url != url:
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args)
        _engine_url = url
    return _engine


def init_trisk_schema() -> None:
    """Init trisk schema.

    Args:
        None.

    Returns:
        None.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    from backend.db import models  # noqa: F401

    SQLModel.metadata.create_all(get_engine())


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Session scope.

    Args:
        None.

    Returns:
        The Generator[Session, None, None] result produced by the operation.

    Side effects:
        May read or write files, database/session state, stdout, subprocesses, or audit records as directed by the implementation and supplied collaborators.
    """
    session = Session(get_engine())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Generator[Session, None, None]:
    """Get session.

    Args:
        None.

    Returns:
        The Generator[Session, None, None] result produced by the operation.

    Side effects:
        None beyond deterministic computation and calls to supplied collaborators.
    """
    with session_scope() as session:
        yield session

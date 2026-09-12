"""Advisory cross-process locks for JSONL append/read (stdlib only; local-first).

Uses ``fcntl`` on POSIX and ``msvcrt`` on Windows. Intended for synthetic scale and
concurrency tests — not a distributed lock service.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl


@contextlib.contextmanager
def jsonl_file_lock(path: Path, *, timeout_seconds: float = 30.0) -> Iterator[None]:
    """Acquire an exclusive advisory lock for one JSONL file.

    Creates a sibling ``<path>.lock`` file. Uses ``msvcrt`` on Windows and ``fcntl`` on POSIX.

    Args:
        path: Target JSONL file (parent dirs created on append, not here).
        timeout_seconds: Max wait before raising ``TimeoutError``.

    Yields:
        None while the lock is held.

    Raises:
        TimeoutError: When lock cannot be acquired within ``timeout_seconds``.
        OSError: When the lock file cannot be opened.

    Side effects:
        Creates or opens ``path.name + ".lock"``; releases lock on context exit.

    Engineering Notes:
        Advisory only — does not prevent unrelated processes that ignore the lock file.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lock_path = target.with_name(target.name + ".lock")
    deadline = time.monotonic() + timeout_seconds
    lock_handle = None
    while lock_handle is None:
        try:
            lock_handle = open(lock_path, "a+b")
        except OSError as exc:
            raise OSError(f"cannot open lock file {lock_path}") from exc
        try:
            if sys.platform == "win32":
                lock_handle.seek(0)
                msvcrt.locking(lock_handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            lock_handle.close()
            lock_handle = None
            if time.monotonic() >= deadline:
                raise TimeoutError(f"lock timeout for {target}") from None
            time.sleep(0.005)
    try:
        yield
    finally:
        if sys.platform == "win32":
            lock_handle.seek(0)
            msvcrt.locking(lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()


def append_jsonl_locked(path: Path, record: dict[str, Any]) -> None:
    """Append one JSON line under an exclusive file lock.

    Args:
        path: Destination JSONL file.
        record: JSON-serializable dict (``ensure_ascii=False``, ``default=str``).

    Side effects:
        Creates parent directories; appends one line; calls ``os.fsync`` on the handle.

    Audit Notes:
        Not duplicate-safe — callers must enforce idempotency keys at a higher layer.
    """
    target = Path(path)
    line = json.dumps(record, ensure_ascii=False, default=str)
    with jsonl_file_lock(target):
        with target.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def read_jsonl_locked(path: Path) -> list[dict[str, Any]]:
    """Read all valid JSONL rows under a shared-style exclusive lock."""
    target = Path(path)
    if not target.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with jsonl_file_lock(target):
        with target.open(encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
    return rows

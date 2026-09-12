"""Lightweight ``Result`` algebra for CLI-friendly success/failure without exceptions.

Prefer ``Ok`` when a value flows; ``Err`` carries stable ``code`` tokens for scripted parsing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class Ok(Generic[T]):
    """Wrap a successful computation product."""

    value: T


@dataclass(frozen=True)
class Err:
    """Carry deterministic failure metadata (no stack trace coupling)."""

    code: str
    message: str


Result = Ok[T] | Err

"""Package version resolution — prefers installed distribution metadata.

Module responsibility:
    Exposes ``resolve_version()`` which returns the installed package version
    string from ``importlib.metadata``, falling back to ``_FALLBACK_VERSION``
    for editable installs and development trees where the distribution metadata
    may not be present.

System placement:
    Called by the ``--version`` CLI flag handler in ``cli.py`` and by any
    component that needs to embed the toolkit version in audit or governance
    output.

Key invariants:
    ``_FALLBACK_VERSION`` must be kept in sync with the ``version`` field in
    ``pyproject.toml`` when releasing.

Side effects:
    None — ``importlib.metadata.version`` performs a metadata lookup only;
    no files are written.

Failure modes:
    ``PackageNotFoundError`` from ``importlib.metadata`` is caught and silenced;
    ``_FALLBACK_VERSION`` is returned instead.
"""

from __future__ import annotations

_FALLBACK_VERSION = "0.2.0"
_PACKAGE_NAME = "windows-network-recovery-toolkit"


def resolve_version() -> str:
    """Return the installed package version, or the fallback string for dev trees.

    Queries ``importlib.metadata`` for the distribution version of
    ``windows-network-recovery-toolkit``.  Any exception (e.g.
    ``PackageNotFoundError`` in an editable install without metadata) is caught
    and ``_FALLBACK_VERSION`` is returned instead.

    Returns:
        A PEP-440-compatible version string (e.g. ``"0.2.0"``).

    Side effects:
        None.
    """
    try:
        from importlib.metadata import version

        return version(_PACKAGE_NAME)
    except Exception:
        return _FALLBACK_VERSION

"""DNS probe façade (delegates to collector ICMP/DNS tooling)."""

from __future__ import annotations

from ..diagnostics.collector import run_command


def nslookup_google_ok(timeout: float = 35.0) -> tuple[bool, str]:
    """Return whether ``nslookup google.com`` succeeds (exit code driven)."""
    code, _out = run_command(["nslookup", "google.com"], timeout=timeout)
    return code == 0, "nslookup google.com"


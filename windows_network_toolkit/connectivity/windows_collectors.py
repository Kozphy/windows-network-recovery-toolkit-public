"""Collect read-only Windows evidence for IPv4/IPv6 path comparison.

The collectors sit before :mod:`dual_stack`: they normalize PowerShell output
into family-specific DNS, route, and partial :class:`~.dual_stack.PathProbe`
records. Commands are limited to ``Resolve-DnsName`` and ``Get-NetRoute`` and
never modify endpoint state. Injecting ``runner`` keeps collection replayable
in tests and permits deterministic failure fixtures.

Collection is intentionally incomplete until the transport probe layer runs.
Callers must preserve the returned ``NOT_TESTED`` states and limitations rather
than treating DNS and route success as end-to-end connectivity.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from .dual_stack import PathProbe, PathState

Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True, slots=True)
class FamilyEvidence:
    """Normalized DNS, route, and partial probe evidence for one family.

    ``probe`` intentionally contains only DNS and route states until the
    transport probe is invoked separately. Consumers should preserve the
    ``limitations`` tuple when exporting or classifying this record.

    Attributes:
        family: Stable display label, either ``IPv4`` or ``IPv6``.
        dns_records: Resolved addresses for the selected family.
        default_routes: Normalized active default-route descriptions.
        probe: Partial path evidence with unexecuted transport fields explicit.
        limitations: Collection gaps or parser/process failures.
    """

    family: str
    dns_records: tuple[str, ...]
    default_routes: tuple[str, ...]
    probe: PathProbe
    limitations: tuple[str, ...] = ()


def _default_runner(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one bounded, non-interactive PowerShell command."""
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=15)


def _validate_family(family: int) -> None:
    """Reject address-family selectors other than IPv4 or IPv6."""
    if family not in (4, 6):
        raise ValueError(f"family must be 4 or 6, got {family!r}")


def _powershell(script: str, runner: Runner) -> tuple[PathState, str, tuple[str, ...]]:
    """Execute a collector command and normalize process-level failures."""
    try:
        result = runner(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ]
        )
    except subprocess.TimeoutExpired:
        return PathState.NOT_TESTED, "", ("PowerShell command timed out",)
    except OSError as exc:
        return PathState.NOT_TESTED, "", (f"PowerShell process could not start: {exc}",)
    if result.returncode != 0:
        return (
            PathState.NOT_TESTED,
            result.stdout.strip(),
            (f"PowerShell command failed with exit code {result.returncode}",),
        )
    return PathState.PASS, result.stdout.strip(), ()


def collect_dns(
    host: str,
    family: int,
    *,
    runner: Runner = _default_runner,
) -> tuple[PathState, tuple[str, ...], tuple[str, ...]]:
    """Resolve A (IPv4) or AAAA (IPv6) records with ``Resolve-DnsName``.

    Args:
        host: Hostname supplied to PowerShell after single-quote escaping.
        family: Address family selector; ``4`` requests A records and ``6``
            requests AAAA records.
        runner: Command runner used for live collection or deterministic tests.

    Returns:
        A tuple containing state, normalized IP strings, and limitations.

    Failure behavior:
        Process launch failures, timeouts, and nonzero exit codes return
        ``NOT_TESTED``. Successful queries with no records return ``FAIL``.
        Malformed JSON returns ``NOT_TESTED`` so callers cannot mistake parser
        failure for a successful DNS result.

    Raises:
        ValueError: If ``family`` is not 4 or 6.
    """
    _validate_family(family)
    record_type = "A" if family == 4 else "AAAA"
    safe_host = host.replace("'", "''")
    script = (
        f"$r = Resolve-DnsName -Name '{safe_host}' -Type {record_type} "
        "-ErrorAction SilentlyContinue | Where-Object { $_.IPAddress }; "
        "$r | Select-Object -ExpandProperty IPAddress | ConvertTo-Json -Compress"
    )
    state, stdout, execution_limits = _powershell(script, runner)
    if state is not PathState.PASS:
        return state, (), execution_limits
    if not stdout:
        return PathState.FAIL, (), (f"No {record_type} records returned",)
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        return PathState.NOT_TESTED, (), ("DNS collector returned unparsable JSON",)
    values = (parsed,) if isinstance(parsed, str) else tuple(parsed)
    return (PathState.PASS if values else PathState.FAIL), values, ()


def collect_default_routes(
    family: int,
    *,
    runner: Runner = _default_runner,
) -> tuple[PathState, tuple[str, ...], tuple[str, ...]]:
    """Collect active default routes using ``Get-NetRoute``.

    Args:
        family: Address family selector for the default route query.
        runner: Command runner used for live collection or deterministic tests.

    Returns:
        A tuple containing state, normalized route descriptions, and limitations.

    Failure behavior:
        Process launch failures, timeouts, and nonzero exit codes return
        ``NOT_TESTED``. Successful queries with no routes return ``FAIL``.
        Malformed JSON returns ``NOT_TESTED``. No route mutation occurs.

    Raises:
        ValueError: If ``family`` is not 4 or 6.
    """
    _validate_family(family)
    address_family = "IPv4" if family == 4 else "IPv6"
    destination = "0.0.0.0/0" if family == 4 else "::/0"
    script = (
        f"$r = Get-NetRoute -AddressFamily {address_family} -DestinationPrefix '{destination}' "
        "-ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Alive' } | "
        "Select-Object InterfaceAlias,NextHop,RouteMetric; "
        "$r | ConvertTo-Json -Compress"
    )
    state, stdout, execution_limits = _powershell(script, runner)
    if state is not PathState.PASS:
        return state, (), execution_limits
    if not stdout:
        return PathState.FAIL, (), (f"No active {address_family} default route",)
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError:
        return PathState.NOT_TESTED, (), ("Route collector returned unparsable JSON",)
    rows = [parsed] if isinstance(parsed, dict) else parsed
    normalized = tuple(
        f"{row.get('InterfaceAlias', '?')} -> {row.get('NextHop', '?')} (metric={row.get('RouteMetric', '?')})"
        for row in rows
    )
    return (PathState.PASS if normalized else PathState.FAIL), normalized, ()


def collect_family_evidence(
    host: str,
    family: int,
    *,
    runner: Runner = _default_runner,
) -> FamilyEvidence:
    """Collect DNS and default-route evidence for one IP family.

    Args:
        host: Hostname to resolve.
        family: Address family selector.
        runner: Command runner used for live collection or deterministic tests.

    Returns:
        ``FamilyEvidence`` with normalized records, routes, partial probe state,
        and limitations. TCP/TLS/HTTP/endpoint fields remain ``NOT_TESTED``.

    Side effects:
        Live calls execute read-only PowerShell commands. Injected test runners
        may have their own side effects, which are outside this module's contract.

    Raises:
        ValueError: If ``family`` is not 4 or 6.
    """
    _validate_family(family)
    dns_state, records, dns_limits = collect_dns(host, family, runner=runner)
    route_state, routes, route_limits = collect_default_routes(family, runner=runner)
    return FamilyEvidence(
        family="IPv4" if family == 4 else "IPv6",
        dns_records=records,
        default_routes=routes,
        probe=PathProbe(dns=dns_state, route=route_state),
        limitations=tuple(
            (*dns_limits, *route_limits, "TCP/TLS/HTTP/endpoint probes not yet executed")
        ),
    )

"""Normalize registry-diff payloads into HKCU proxy key hints.

Module responsibility:
    Converts nested ``before`` / ``after`` blobs (fixture JSON, tests, or sanitized API context) into
    :class:`RegistryDiffHint` so :mod:`evidence.attribution_engine` can cite registry polls without importing ``winreg``.

System placement:
    Consumed exclusively by attribution scoring; orthogonal to ``src.proxy_guard`` live readers.

Input assumptions:
    Keys may vary in casing/path separators—callers flatten heuristically. Missing dict branches yield
    empty hints (still valid).

Output guarantees:
    :func:`describe_diff` returns deterministic strings comparable across runs for identical hints.

Raises:
    None from public helpers—conversion tolerates malformed maps by omission.

Audit Notes:
    Summaries omit raw host identifiers when upstream redaction honors ``platform_core`` privacy patterns;
    auditors still cannot infer registry writer PID from diff text alone—pair with Sysmon extracts when required.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RegistryDiffHint:
    """Coarse WinINET HKCU proxy field pairing used for narration.

    Fields map to textual ``ProxyEnable`` / ``ProxyServer`` string forms as captured in fixtures—not necessarily decimal DWORD typing.
    """

    proxy_enable_before: str | None = None
    proxy_enable_after: str | None = None
    proxy_server_before: str | None = None
    proxy_server_after: str | None = None


def _flatten_keys(d: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        out[str(k).lower().replace(" ", "").replace("\\", "").replace("/", "")] = v
    return out


def _get_any(dflat: dict[str, Any], *needles: str) -> str | None:
    for needle in needles:
        n = needle.lower()
        for k, v in dflat.items():
            if v is None:
                continue
            kl = str(k).lower()
            if n in kl or kl.endswith(n):
                return str(v)
    return None


def parse_registry_hint(obj: dict[str, Any] | None) -> RegistryDiffHint:
    """Coerce heterogeneous dict trees into typed proxy deltas.

    Args:
        obj: Either ``{"before": {...}, "after": {...}}`` or flat dict treated as BEFORE slice when
            ``after`` absent.

    Returns:
        :class:`RegistryDiffHint`; empty hint when ``obj`` is falsy.

    Constraints:
        Only ``ProxyEnable`` / ``ProxyServer`` analog keys are surfaced—PAC/BypassRemainder fields ignored here.
    """

    if not obj:
        return RegistryDiffHint()
    before_raw = obj.get("before") if isinstance(obj.get("before"), dict) else obj
    after_raw = obj.get("after") if isinstance(obj.get("after"), dict) else {}
    merged_before = _flatten_keys(dict(before_raw)) if isinstance(before_raw, dict) else {}
    merged_after = _flatten_keys(dict(after_raw)) if isinstance(after_raw, dict) else {}

    return RegistryDiffHint(
        proxy_enable_before=_get_any(merged_before, "proxyenable"),
        proxy_enable_after=_get_any(merged_after, "proxyenable"),
        proxy_server_before=_get_any(merged_before, "proxyserver"),
        proxy_server_after=_get_any(merged_after, "proxyserver"),
    )


def describe_diff(hint: RegistryDiffHint) -> str:
    """Render human-readable deltas for EvidenceItem ingestion.

    Args:
        hint: Parsed proxy columns.

    Returns:
        Concatenated ``ProxyEnable``/``ProxyServer`` transitions or sentinel ``no_proxy_key_delta_in_hint``.

    Failure modes:
        ``None`` vs empty string distinctions preserved—callers relying on sentinel string should treat as categorical.
    """

    parts: list[str] = []
    if hint.proxy_enable_before != hint.proxy_enable_after and (
        hint.proxy_enable_before is not None or hint.proxy_enable_after is not None
    ):
        parts.append(f"ProxyEnable {hint.proxy_enable_before!r}->{hint.proxy_enable_after!r}")
    if hint.proxy_server_before != hint.proxy_server_after and (
        hint.proxy_server_before is not None or hint.proxy_server_after is not None
    ):
        parts.append(f"ProxyServer {hint.proxy_server_before!r}->{hint.proxy_server_after!r}")
    return "; ".join(parts) if parts else "no_proxy_key_delta_in_hint"

"""Proxy classification facade for windows_network_toolkit consumers.

Module responsibility:
    Provides two entry points for proxy-state classification: one that collects
    live Windows evidence before classifying, and one that accepts pre-collected
    snapshots.  Both delegate to ``src.platform_core.classification.engine`` for
    the actual decision logic and wrap results in the toolkit's ``ClassificationResult``
    value object.

System placement:
    Called by ``proof.py``, ``report.py``, and the ``classify`` CLI command.
    Test fixtures inject via the ``inject`` parameter to avoid live registry reads.

Key invariants:
    Classification labels produced here are informational triage labels — they are
    observations, not proof of compromise or malicious intent.  ``limitations[]``
    must be preserved in all outputs.

Side effects:
    When ``inject`` is ``None``, ``classify_from_live`` performs live Windows
    registry reads (WinINET/WinHTTP) and port-listener probes through
    ``collect_attribution`` and ``detect_proxy_owner``.

Failure modes:
    Registry access errors surface as exceptions from ``collect_attribution``.
    Missing ``primary_classification`` key in ``inject`` raises ``KeyError``.

Audit Notes:
    Classification decisions inform remediation eligibility; any change to label
    semantics here affects ``proof.py``, ``report.py``, and policy-gate logic in
    ``src.platform_core.policy``.
"""

from __future__ import annotations

from typing import Any

from src.platform_core.attribution.collector import collect_attribution
from src.platform_core.attribution.models import ProcessAttribution, ProxyStateSnapshot
from src.platform_core.classification.engine import classify_proxy
from windows_network_toolkit.models import ClassificationResult
from windows_network_toolkit.proxy_owner import detect_proxy_owner


def classify_from_live(
    *,
    inject: dict[str, Any] | None = None,
    inject_state: dict[str, Any] | None = None,
    **kwargs: Any,
) -> ClassificationResult:
    """Classify current proxy state from live Windows evidence or a test fixture.

    When ``inject`` is supplied the function builds a ``ClassificationResult``
    directly from the provided dict, bypassing all live OS calls.  This path is
    intended for deterministic unit tests and fixture-based regression coverage.

    When ``inject`` is ``None`` the function collects live state via
    ``collect_attribution`` and ``detect_proxy_owner``, then forwards the enriched
    signal set to ``classify_proxy``.

    Args:
        inject: Optional pre-built classification dict keyed with
            ``primary_classification``, ``secondary_signals``, ``severity``,
            ``confidence``, ``reasoning``, ``evidence``,
            ``recommended_next_actions``, and ``limitations``.
            Missing keys fall back to safe defaults (empty lists / 0.0 / "info").
        inject_state: Unused by this function; accepted for forward-compatibility
            with callers that pass combined inject bundles.
        **kwargs: Forwarded to ``collect_attribution`` and ``detect_proxy_owner``
            when performing live evidence collection.  Recognised signal flags:
            ``registry_rewrite_observed``, ``writer_listener_mismatch``,
            ``repeated_reappearance``, ``reverter_suspected``.

    Returns:
        A ``ClassificationResult`` with ``primary_classification``,
        ``secondary_signals``, ``severity``, ``confidence``, ``reasoning``,
        ``evidence``, ``recommended_next_actions``, and ``limitations``.

    Side effects:
        Live path: reads HKCU WinINET/WinHTTP registry keys and probes open
        TCP ports on the host.  Inject path: no side effects.

    Audit Notes:
        The label produced here propagates to ``proof.py`` and the policy gate.
        Any change to label semantics requires updating the ADR for proxy-state
        classification (``docs/adr/0007-proxy-transition-full-state-classification.md``).
    """
    if inject:
        return ClassificationResult(
            primary_classification=str(inject["primary_classification"]),
            secondary_signals=list(inject.get("secondary_signals") or []),
            severity=str(inject.get("severity") or "info"),
            confidence=float(inject.get("confidence") or 0.0),
            reasoning=str(inject.get("reasoning") or ""),
            evidence=list(inject.get("evidence") or []),
            recommended_next_actions=list(inject.get("recommended_next_actions") or []),
            limitations=list(inject.get("limitations") or []),
        )

    snap = collect_attribution(**kwargs)
    owner = detect_proxy_owner(**kwargs)
    listener_detected = bool(owner.get("listener_found"))
    raw = classify_proxy(
        snap.proxy_state,
        snap.listener,
        listener_detected=listener_detected,
        registry_rewrite_observed=bool(kwargs.get("registry_rewrite_observed")),
        writer_listener_mismatch=bool(kwargs.get("writer_listener_mismatch")),
        repeated_reappearance=bool(kwargs.get("repeated_reappearance")),
        reverter_suspected=bool(kwargs.get("reverter_suspected")),
    )
    return ClassificationResult(**raw)


def classify_from_snapshots(
    proxy: ProxyStateSnapshot,
    process: ProcessAttribution,
    *,
    listener_detected: bool = False,
    **flags: Any,
) -> ClassificationResult:
    """Classify proxy state from pre-collected attribution snapshots.

    Accepts caller-supplied snapshots rather than reading live OS state,
    making this suitable for replay, batch analysis, and deterministic testing.

    Args:
        proxy: Proxy-state snapshot containing WinINET/WinHTTP field values.
        process: Process-attribution snapshot describing the observed listener
            or registry writer (may represent an absent process).
        listener_detected: Whether a process was confirmed listening on the
            configured proxy port at snapshot time.
        **flags: Additional boolean signal flags forwarded to ``classify_proxy``
            (e.g. ``registry_rewrite_observed``, ``reverter_suspected``).

    Returns:
        A ``ClassificationResult`` with the classification label, confidence,
        reasoning, evidence list, and limitations.

    Side effects:
        None — all inputs are caller-supplied.
    """
    raw = classify_proxy(proxy, process, listener_detected=listener_detected, **flags)
    return ClassificationResult(**raw)

"""Structured evidence records for Proxy Guard pipeline output.

Module responsibility:
    Normalize registry-drift and connectivity-check observations into compact evidence items
    embedded in pipeline JSONL and stdout decision payloads.

System placement:
    Called by :mod:`src.proxy_guard.guard` after diff + connectivity validation and before
    emission to ``logs/proxy_guard_pipeline_audit.jsonl``.

Key invariants:
    - Evidence rows are append-only facts; they do not assert causality.
    - ``confidence_score`` values are heuristic quality hints, not forensic certainty.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .connectivity import ConnectivityValidation


@dataclass(frozen=True)
class EvidenceItem:
    """Single evidence row persisted in decision/audit payloads.

    Attributes:
        source: Evidence source tag (for example ``registry_polling``).
        observed_at: UTC timestamp string inherited from capture context.
        target_key: Registry or logical target namespace.
        target_value_name: Value/check identifier under the target namespace.
        old_value: Prior value when known.
        new_value: Current observed value.
        confidence_score: Heuristic confidence in observation quality.
        notes: Compact tags for query and incident triage.
        raw_excerpt: Bounded raw output snippet for troubleshooting.
    """

    source: str
    observed_at: str
    target_key: str
    target_value_name: str
    old_value: Any
    new_value: Any
    confidence_score: float
    notes: tuple[str, ...]
    raw_excerpt: str

    def to_jsonable(self) -> dict[str, Any]:
        """To jsonable.

        Args:
            None.

        Returns:
            The dict[str, Any] result produced by the operation.

        Side effects:
            None beyond deterministic computation and calls to supplied collaborators.
        """
        return {
            "source": self.source,
            "observed_at": self.observed_at,
            "target_key": self.target_key,
            "target_value_name": self.target_value_name,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "confidence_score": self.confidence_score,
            "notes": list(self.notes),
            "raw_excerpt": self.raw_excerpt,
        }


def build_registry_change_evidence(
    *,
    observed_at: str,
    value_name: str,
    old_value: Any,
    new_value: Any,
) -> EvidenceItem:
    """Create one registry change evidence row for HKCU WinINET fields.

    Args:
        observed_at: UTC timestamp string for when the change was observed.
        value_name: WinINET registry value name (for example ``ProxyEnable``).
        old_value: Value before detected change.
        new_value: Value after detected change.

    Returns:
        EvidenceItem: Structured evidence row tagged as ``registry_polling``.
    """
    return EvidenceItem(
        source="registry_polling",
        observed_at=observed_at,
        target_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        target_value_name=value_name,
        old_value=old_value,
        new_value=new_value,
        confidence_score=0.6,
        notes=("polling_detected_change", "best_effort_only"),
        raw_excerpt=f"{value_name}: {old_value!r} -> {new_value!r}",
    )


def build_connectivity_evidence(
    *,
    observed_at: str,
    validation: ConnectivityValidation,
) -> list[EvidenceItem]:
    """Translate post-change connectivity checks into evidence rows.

    Args:
        observed_at: UTC timestamp string for emitted evidence.
        validation: Connectivity validation bundle containing post-change probe results.

    Returns:
        list[EvidenceItem]: One row per post-change DNS/TCP/HTTPS check.

    Side effects:
        None. Pure transformation from in-memory validation data.
    """
    items: list[EvidenceItem] = []
    post = validation.post_change
    checks = (
        ("post_change_tcp443_check", "tcp_443_google", post.tcp_443_google.ok, post.tcp_443_google),
        ("post_change_https_check", "https_google", post.https_google.ok, post.https_google),
        (
            "post_change_https_check",
            "https_microsoft",
            post.https_microsoft.ok,
            post.https_microsoft,
        ),
        ("post_change_dns_check", "dns_google", post.dns_google.ok, post.dns_google),
    )
    for source, name, ok, probe in checks:
        items.append(
            EvidenceItem(
                source=source,
                observed_at=observed_at,
                target_key="connectivity",
                target_value_name=name,
                old_value=None,
                new_value=ok,
                confidence_score=0.8 if ok else 0.7,
                notes=(f"returncode={probe.returncode}",),
                raw_excerpt=(probe.stdout or probe.stderr or "")[:500],
            ),
        )
    return items

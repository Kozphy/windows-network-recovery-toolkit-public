"""Optional reputation API plugins — no hard-coded API keys."""

from __future__ import annotations

import os
from typing import Protocol

from .models import WebsiteRiskEvidence


class ReputationPlugin(Protocol):
    """Represent the reputation plugin type.

    Key fields:
        name: Structured value carried by this type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    name: str

    def is_configured(self) -> bool:
        """Return is configured.

        Returns:
            The computed `bool` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        ...

    def lookup(self, url: str) -> list[WebsiteRiskEvidence]:
        """Return lookup.

        Args:
            url: url supplied by the caller.

        Returns:
            The computed `list[WebsiteRiskEvidence]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        ...


class VirusTotalPlugin:
    """Represent the virus total plugin type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    name = "virustotal"

    def is_configured(self) -> bool:
        """Return is configured.

        Returns:
            The computed `bool` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip())

    def lookup(self, url: str) -> list[WebsiteRiskEvidence]:
        """Return lookup.

        Args:
            url: url supplied by the caller.

        Returns:
            The computed `list[WebsiteRiskEvidence]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if not key:
            return []
        return [
            WebsiteRiskEvidence(
                signal="reputation_virustotal",
                observed="not_queried_live_in_tests",
                weight=0.0,
                detail="Configure VIRUSTOTAL_API_KEY to enable live lookups.",
            )
        ]


class GoogleSafeBrowsingPlugin:
    """Represent the google safe browsing plugin type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    name = "google_safe_browsing"

    def is_configured(self) -> bool:
        """Return is configured.

        Returns:
            The computed `bool` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return bool(os.environ.get("GOOGLE_SAFEBROWSING_API_KEY", "").strip())

    def lookup(self, url: str) -> list[WebsiteRiskEvidence]:
        """Return lookup.

        Args:
            url: url supplied by the caller.

        Returns:
            The computed `list[WebsiteRiskEvidence]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        if not self.is_configured():
            return []
        return [
            WebsiteRiskEvidence(
                signal="reputation_safe_browsing",
                observed="not_queried_live_in_tests",
                weight=0.0,
                detail="Configure GOOGLE_SAFEBROWSING_API_KEY to enable live lookups.",
            )
        ]


class URLHausPlugin:
    """Represent the urlhaus plugin type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    name = "urlhaus"

    def is_configured(self) -> bool:
        """Return is configured.

        Returns:
            The computed `bool` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return bool(os.environ.get("URLHAUS_API_KEY", "").strip())

    def lookup(self, url: str) -> list[WebsiteRiskEvidence]:
        """Return lookup.

        Args:
            url: url supplied by the caller.

        Returns:
            The computed `list[WebsiteRiskEvidence]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        if not self.is_configured():
            return []
        return []


class PhishTankPlugin:
    """Represent the phish tank plugin type.

    Side effects:
        None.

    Audit Notes:
        Use this structure as evidence-backed metadata; it does not prove
        causality or authorize action by itself.
    """
    name = "phishtank"

    def is_configured(self) -> bool:
        """Return is configured.

        Returns:
            The computed `bool` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        return bool(os.environ.get("PHISHTANK_API_KEY", "").strip())

    def lookup(self, url: str) -> list[WebsiteRiskEvidence]:
        """Return lookup.

        Args:
            url: url supplied by the caller.

        Returns:
            The computed `list[WebsiteRiskEvidence]` value.

        Side effects:
            None.

        Audit Notes:
            Decision intent is limited to evidence-backed classification or
            routing for the supplied inputs; callers should preserve source
            evidence, policy context, and limitations with the result.
        """
        if not self.is_configured():
            return []
        return []


def default_plugins() -> list[ReputationPlugin]:
    """Return default plugins.

    Returns:
        The computed `list[ReputationPlugin]` value.

    Side effects:
        None.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    return [
        VirusTotalPlugin(),
        GoogleSafeBrowsingPlugin(),
        URLHausPlugin(),
        PhishTankPlugin(),
    ]


def run_reputation_plugins(
    url: str,
    plugins: list[ReputationPlugin] | None = None,
) -> tuple[list[WebsiteRiskEvidence], list[str]]:
    """Run reputation plugins.

    Args:
        url: url supplied by the caller.
        plugins: plugins supplied by the caller.

    Returns:
        The computed `tuple[list[WebsiteRiskEvidence], list[str]]` value.

    Side effects:
        Executes the configured evaluation or processing flow.

    Audit Notes:
        Decision intent is limited to evidence-backed classification or
        routing for the supplied inputs; callers should preserve source
        evidence, policy context, and limitations with the result.
    """
    used: list[str] = []
    evidence: list[WebsiteRiskEvidence] = []
    for plugin in plugins or default_plugins():
        if plugin.is_configured():
            used.append(plugin.name)
            evidence.extend(plugin.lookup(url))
    return evidence, used

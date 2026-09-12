"""BrowserAdapter abstract base — Chromium-first; Firefox later.

Module responsibility:
    Define the ``BrowserAdapter`` ABC that all concrete browser adapters must
    implement.  The interface covers installation detection, profile discovery,
    metadata enrichment, extension/policy/preference collection, HAR import,
    and optional controlled Playwright probes.

System placement:
    Subclassed by ``ChromiumProfileMixin`` (shared logic), ``EdgeAdapter``, and
    ``ChromeAdapter``.  Consumed via the ``get_adapter`` factory.

Key invariants:
    * Every abstract method returns metadata only — no cookie values or secrets.
    * ``run_controlled_probe`` default returns ``available=False``; subclasses may
      override when the ``[browser]`` optional dependency is installed.
    * ``import_har`` is a thin file-read helper; redaction is the caller's responsibility.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from windows_network_toolkit.diagnostics.browser_profile.models import (
    BrowserExtensionEvidence,
    BrowserNetworkPreferenceEvidence,
    BrowserPolicyEvidence,
    BrowserProfileEvidence,
    BrowserSiteStateEvidence,
)


class BrowserAdapter(ABC):
    """Abstract adapter for a user-agent family."""

    name: str = "unknown"

    @abstractmethod
    def detect_installation(self) -> dict[str, Any]:
        """Return installed path/version or empty if not found."""

    @abstractmethod
    def discover_profiles(self) -> list[BrowserProfileEvidence]:
        """List local profiles (metadata only)."""

    @abstractmethod
    def collect_profile_metadata(self, profile: BrowserProfileEvidence) -> BrowserProfileEvidence:
        """Enrich a profile record."""

    @abstractmethod
    def collect_policy_metadata(self) -> list[BrowserPolicyEvidence]:
        """Read managed policy keys relevant to network/privacy."""

    @abstractmethod
    def collect_extension_metadata(
        self, profile: BrowserProfileEvidence
    ) -> list[BrowserExtensionEvidence]:
        """List extension IDs/names/enabled/permissions (no secrets)."""

    @abstractmethod
    def collect_site_state_metadata(
        self, domain: str, profile: BrowserProfileEvidence
    ) -> BrowserSiteStateEvidence:
        """Cookie count/meta + SW/cache flags for domain; never cookie values."""

    @abstractmethod
    def collect_network_preferences(
        self, profile: BrowserProfileEvidence
    ) -> BrowserNetworkPreferenceEvidence:
        """Secure DNS / proxy prefs from Preferences JSON."""

    def import_har(self, path: Path) -> dict[str, Any]:
        """Load a raw HAR file from disk as a dict.

        Args:
            path: Filesystem path to a ``.har`` JSON file.

        Returns:
            Parsed HAR dict.  The caller is responsible for redaction before analysis.
        """
        import json

        return json.loads(path.read_text(encoding="utf-8"))

    def run_controlled_probe(self, url: str, mode: str) -> dict[str, Any]:
        """Optional Playwright ephemeral/persistent toolkit profile.

        Mode is ``private`` (ephemeral) or ``stateful`` (dedicated toolkit profile).
        Never mutates the user's real profile. Default returns not-available.
        """
        return {
            "mode": mode,
            "url": url,
            "available": False,
            "limitations": [
                "Controlled Playwright probe not executed; use HAR import or install [browser] extra.",
            ],
        }

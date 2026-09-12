"""Google Chrome Chromium adapter.

Module responsibility:
    Concrete ``BrowserAdapter`` for Google Chrome on Windows.  Delegates all
    profile inspection logic to ``ChromiumProfileMixin``, binding the Chrome
    ``User Data`` directory candidates and process names.

System placement:
    Returned by ``get_adapter("chrome")`` and by ``get_adapter("auto")`` when
    Edge is not installed.

Key invariants:
    * Inspection is read-only; no Chrome profile files are written.
    * ``LOCALAPPDATA`` environment variable locates the User Data directory.
"""

from __future__ import annotations

import os
from pathlib import Path

from windows_network_toolkit.diagnostics.browser_profile.adapters.base import BrowserAdapter
from windows_network_toolkit.diagnostics.browser_profile.adapters.chromium import (
    ChromiumProfileMixin,
)
from windows_network_toolkit.diagnostics.browser_profile.models import (
    BrowserExtensionEvidence,
    BrowserNetworkPreferenceEvidence,
    BrowserPolicyEvidence,
    BrowserProfileEvidence,
    BrowserSiteStateEvidence,
)


class ChromeAdapter(ChromiumProfileMixin, BrowserAdapter):
    """BrowserAdapter for Google Chrome using shared ChromiumProfileMixin logic.

    Binds Chrome-specific User Data path candidates and process names, then
    delegates every ``BrowserAdapter`` abstract method to ``ChromiumProfileMixin``.
    """

    name = "chrome"
    browser_name = "chrome"
    process_names = ("chrome.exe",)

    def __init__(self) -> None:
        """Initialize Chrome-specific User Data path candidates.

        Args:
            None.

        Returns:
            None.

        Side effects:
            Reads ``LOCALAPPDATA`` from the process environment."""
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        self.user_data_candidates = (local / "Google" / "Chrome" / "User Data",)

    def detect_installation(self) -> dict:
        """Return whether the browser profile root is available.

        Args:
            None.

        Returns:
            Dict with ``installed`` status, browser name, and optional user data directory.

        Side effects:
            Reads filesystem metadata for candidate profile directories."""
        return super().detect_installation()

    def discover_profiles(self) -> list[BrowserProfileEvidence]:
        """Discover browser profiles under the configured User Data root.

        Args:
            None.

        Returns:
            List of ``BrowserProfileEvidence`` objects for discovered profiles.

        Side effects:
            Reads profile directory metadata and may enumerate browser processes."""
        return super().discover_profiles()

    def collect_profile_metadata(self, profile: BrowserProfileEvidence) -> BrowserProfileEvidence:
        """Refresh metadata for a discovered browser profile.

        Args:
            profile: Profile evidence object to enrich.

        Returns:
            Updated ``BrowserProfileEvidence`` with profile name/open-state metadata.

        Side effects:
            Reads profile preference files and may enumerate browser processes."""
        return super().collect_profile_metadata(profile)

    def collect_policy_metadata(self) -> list[BrowserPolicyEvidence]:
        """Collect browser policy metadata relevant to diagnostics.

        Args:
            None.

        Returns:
            List of ``BrowserPolicyEvidence`` objects.

        Side effects:
            Reads managed policy files and environment hints; does not modify browser state."""
        return super().collect_policy_metadata()

    def collect_extension_metadata(
        self, profile: BrowserProfileEvidence
    ) -> list[BrowserExtensionEvidence]:
        """Collect extension metadata for one browser profile.

        Args:
            profile: Profile whose extension settings should be inspected.

        Returns:
            List of ``BrowserExtensionEvidence`` objects.

        Side effects:
            Reads the profile ``Preferences`` JSON file only."""
        return super().collect_extension_metadata(profile)

    def collect_site_state_metadata(
        self, domain: str, profile: BrowserProfileEvidence
    ) -> BrowserSiteStateEvidence:
        """Collect redacted site-state metadata for one domain/profile pair.

        Args:
            domain: Domain to match against cookies and storage paths.
            profile: Profile whose site state should be inspected.

        Returns:
            ``BrowserSiteStateEvidence`` with counts and redacted metadata.

        Side effects:
            Reads profile files and temporary SQLite copies; never writes live browser databases."""
        return super().collect_site_state_metadata(domain, profile)

    def collect_network_preferences(
        self, profile: BrowserProfileEvidence
    ) -> BrowserNetworkPreferenceEvidence:
        """Collect browser network preference metadata for one profile.

        Args:
            profile: Profile whose network preferences should be inspected.

        Returns:
            ``BrowserNetworkPreferenceEvidence`` with DNS-over-HTTPS and proxy settings.

        Side effects:
            Reads the profile ``Preferences`` JSON file only."""
        return super().collect_network_preferences(profile)

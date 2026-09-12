"""Placeholder for authoritative Event Log correlation (Sysmon/EventID pipelines)."""

from __future__ import annotations

from typing import Any

from platform_core.events import ActorAttribution


class WindowsEventLogAttributionProvider:
    """Returns **unsupported** until an explicit secure reader is configured."""

    name = "windows_eventlog_stub"

    def describe(self) -> str:
        """Provide describe behavior for toolkit workflows.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        return "Stub — future integration for tamper-aware registry correlation (off by default)."

    def attribute(self, context: dict[str, Any]) -> ActorAttribution:
        """Provide attribute behavior for toolkit workflows.

        Args:
            context: Value supplied by the caller for context.

        Returns:
            Computed result for the requested operation.

        Side effects:
            None.
        """
        want = bool(context.get("enable_eventlog_experimental"))
        if not want:
            return ActorAttribution(
                confidence="none",
                method="eventlog_disabled",
                notes=[
                    "Event Log correlation not enabled.",
                    "No proof-level attribution without configured providers.",
                ],
                provider=self.name,
                details={},
            )
        return ActorAttribution(
            confidence="none",
            method="eventlog_not_implemented",
            notes=["Experimental channel not wired in this prototype build."],
            provider=self.name,
            details={},
        )

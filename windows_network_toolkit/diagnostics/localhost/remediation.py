"""Preview-only remediation recommendations for localhost diagnose.

Module responsibility:
    Generate an ordered list of PREVIEW and BLOCK ``RemediationPreviewItem``
    objects for a given classification.  Nothing in this module executes any
    action; it only describes what *could* be done and whether policy permits
    it.  Safety blocks (firewall, auto proxy-disable) are always appended
    regardless of classification.

System placement:
    Called by ``localhost/runner.py`` when ``remediation_preview=True``.
    The output is embedded in the report's ``remediation_preview`` field and
    is also consumed by the CLI render step for operator guidance.

Key invariants:
    * No item with ``policy_decision="BLOCK"`` may transition to
      ``"EXECUTE"`` within this module; execution gates live in separate
      gated CLI commands.
    * ``block_firewall_change`` and ``block_auto_proxy_disable`` are always
      appended — CONNECTION_REFUSED is not firewall proof, and a localhost
      listener failure alone does not justify proxy-disable.
    * ``proxy_remediation_preview_only`` requires ``requires_confirmation=True``
      and references the separate ``proxy-disable`` gated command.

Side effects:
    None.  Pure functions; no subprocesses, no registry access.

Failure modes:
    None; always returns a list.  An empty *nearby_ports* or absent
    *service_name* simply omits those optional preview items.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .classifier import ClassificationResult


@dataclass
class RemediationPreviewItem:
    """A single policy-gated remediation suggestion (never auto-executed).

    Attributes:
        action_id: Stable identifier for this action type (e.g.
            ``"reopen_application"``, ``"block_firewall_change"``).
        summary: Short operator-facing description of the proposed action.
        detail: Longer explanation including any command or reference.
        policy_decision: ``"PREVIEW"`` (actionable with confirmation) or
            ``"BLOCK"`` (explicitly disallowed by safety policy).
        justification: Reason for the decision; cited in audit output.
        requires_confirmation: When ``True``, a typed confirmation token must
            be provided before any downstream system executes the action.
        mutates: Identifiers of system components that would be changed
            (e.g. ``["wininet_proxy"]``, ``["firewall"]``); empty for
            read-only or block items.
    """

    action_id: str
    summary: str
    detail: str
    policy_decision: str  # PREVIEW | BLOCK
    justification: str
    requires_confirmation: bool = True
    mutates: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this object to a JSON-compatible dictionary.

        Args:
            None.

        Returns:
            Dict containing the object's public evidence fields.

        Side effects:
            None."""
        return {
            "action_id": self.action_id,
            "summary": self.summary,
            "detail": self.detail,
            "policy_decision": self.policy_decision,
            "justification": self.justification,
            "requires_confirmation": self.requires_confirmation,
            "mutates": list(self.mutates),
        }


def build_remediation_preview(
    classification: ClassificationResult,
    *,
    target_url: str,
    ipv4_only_listener: bool = False,
    ipv6_only_listener: bool = False,
    nearby_ports: list[int] | None = None,
    service_name: str | None = None,
) -> list[RemediationPreviewItem]:
    """Generate safe PREVIEW/BLOCK recommendations for *classification*; never auto-executes.

    Always includes ``reopen_application`` (PREVIEW), the two hard BLOCK items
    for firewall and proxy-disable, and a service-restart block/preview based
    on whether *service_name* was deterministically identified.  Additional
    optional items (IPv4/IPv6 retry, port-change suggestion, proxy preview) are
    added when their conditions are met.

    Args:
        classification: Classifier output; ``code`` drives which optional
            items are appended.
        target_url: The failing URL; embedded in the reopen-app suggestion.
        ipv4_only_listener: When ``True``, adds a ``retry_ipv4`` PREVIEW item.
        ipv6_only_listener: When ``True``, adds a ``retry_ipv6`` PREVIEW item.
        nearby_ports: Non-empty list causes a ``consider_new_port`` PREVIEW
            item to be added (weak evidence only).
        service_name: When set, adds a ``restart_allowlisted_service_preview``
            item (still PREVIEW and requires_confirmation); when absent, adds a
            ``block_generic_restart`` BLOCK item instead.

    Returns:
        Ordered list of ``RemediationPreviewItem`` objects.  Always at least 3
        items (reopen, block-firewall, block-auto-proxy-disable).

    Audit note:
        ``LOCALHOST_PROXY_INTERFERENCE`` triggers ``proxy_remediation_preview_only``
        which references the gated ``proxy-disable`` command.  This is the only
        path in ``localhost-diagnose`` that mentions proxy mutation.
    """

    items: list[RemediationPreviewItem] = []
    code = classification.code

    items.append(
        RemediationPreviewItem(
            action_id="reopen_application",
            summary="Reopen the application that created this localhost page",
            detail=f"After the app is listening again, refresh {target_url}.",
            policy_decision="PREVIEW",
            justification="No listener / connection refused most often means the hosting app is not running.",
            requires_confirmation=False,
            mutates=[],
        )
    )

    if ipv4_only_listener:
        items.append(
            RemediationPreviewItem(
                action_id="retry_ipv4",
                summary="Retry using 127.0.0.1",
                detail="Listener appears IPv4-only; browsers resolving to ::1 may refuse.",
                policy_decision="PREVIEW",
                justification="Address-family bind mismatch observed.",
                requires_confirmation=False,
                mutates=[],
            )
        )
    if ipv6_only_listener:
        items.append(
            RemediationPreviewItem(
                action_id="retry_ipv6",
                summary="Retry using http://[::1]:<port>/…",
                detail="Listener appears IPv6-only.",
                policy_decision="PREVIEW",
                justification="Address-family bind mismatch observed.",
                requires_confirmation=False,
                mutates=[],
            )
        )

    if code == "LOCALHOST_PORT_CHANGED_POSSIBLE" and nearby_ports:
        port = nearby_ports[0]
        items.append(
            RemediationPreviewItem(
                action_id="consider_new_port",
                summary=f"Consider whether the app moved to port {port}",
                detail=(
                    "Nearby listener evidence is weak. Confirm same process/executable before changing bookmarks."
                ),
                policy_decision="PREVIEW",
                justification="Bounded nearby-listener correlation only — not proof of port replacement.",
                requires_confirmation=False,
                mutates=[],
            )
        )

    if code == "LOCALHOST_PROXY_INTERFERENCE":
        items.append(
            RemediationPreviewItem(
                action_id="proxy_remediation_preview_only",
                summary="Preview existing proxy remediation (do not auto-disable)",
                detail=(
                    "Use `python -m windows_network_toolkit proxy-disable --dry-run true` only if "
                    "dead localhost proxy is separately corroborated. Do not disable proxy merely "
                    "because a localhost page failed."
                ),
                policy_decision="PREVIEW",
                justification="Policy gate keeps proxy mutation preview-only without typed confirmation.",
                requires_confirmation=True,
                mutates=["wininet_proxy"],
            )
        )

    if service_name:
        items.append(
            RemediationPreviewItem(
                action_id="restart_allowlisted_service_preview",
                summary=f"Preview restart of identified service '{service_name}'",
                detail="Execution requires existing ALLOW policy and typed confirmation — not performed here.",
                policy_decision="PREVIEW",
                justification="Service was deterministically identified; still preview-only by default.",
                requires_confirmation=True,
                mutates=["windows_service"],
            )
        )
    else:
        items.append(
            RemediationPreviewItem(
                action_id="block_generic_restart",
                summary="Do not restart arbitrary executables or services",
                detail="No deterministically identified Windows service for this listener.",
                policy_decision="BLOCK",
                justification="Safety policy forbids fabricating restart commands for unknown processes.",
                requires_confirmation=True,
                mutates=[],
            )
        )

    # Always block firewall / proxy auto-mutation
    items.append(
        RemediationPreviewItem(
            action_id="block_firewall_change",
            summary="Do not modify firewall rules automatically",
            detail="CONNECTION_REFUSED is not firewall proof.",
            policy_decision="BLOCK",
            justification="Toolkit safety policy blocks firewall changes from diagnose.",
            mutates=["firewall"],
        )
    )
    items.append(
        RemediationPreviewItem(
            action_id="block_auto_proxy_disable",
            summary="Do not automatically disable the system proxy",
            detail="Proxy disable remains a separate gated command.",
            policy_decision="BLOCK",
            justification="Localhost listener failure is usually unrelated to system proxy state.",
            mutates=["wininet_proxy"],
        )
    )
    return items


def policy_envelope(*, remediation_requested: bool) -> dict[str, Any]:
    """Return the default policy decision block for a localhost-diagnose run.

    Always yields ``decision="PREVIEW"`` and ``dry_run=True``.  Lists the five
    actions that are unconditionally blocked (firewall modify, proxy disable,
    registry write, service restart, process kill) regardless of classification.

    Args:
        remediation_requested: Echoed back in the envelope to indicate whether
            the caller requested remediation preview items.

    Returns:
        Dict suitable for the ``policy`` field of the diagnose report and the
        governance envelope.
    """

    return {
        "decision": "PREVIEW",
        "execution_authority": "preview_only",
        "dry_run": True,
        "remediation_requested": remediation_requested,
        "justification": (
            "localhost-diagnose is read-only; remediation items are previews unless an existing "
            "gated command is separately confirmed."
        ),
        "blocked_automatic_actions": [
            "firewall_modify",
            "proxy_disable",
            "registry_write",
            "service_restart",
            "process_kill",
        ],
    }

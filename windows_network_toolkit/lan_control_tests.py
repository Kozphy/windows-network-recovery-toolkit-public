"""LAN privacy control tests (CTRL-LAN-001 through CTRL-LAN-008).

Module responsibility:
    Evaluate management controls against inventory, watch, router, and classification
    evidence; emit PASS/FAIL/PARTIAL/NOT_TESTED results with remediation hints.

System placement:
    Invoked by ``lan-control-tests`` CLI and ``lan_privacy.runner`` executive pipeline.

Key invariants:
    * Results are management information — not audit opinions or security verdicts.
    * Controls reference evidence types; missing evidence yields NOT_TESTED or PARTIAL.
    * ``CONTROL_REGISTRY`` is the canonical definition set for all eight controls.

Side effects:
    * None — pure evaluation over in-memory evidence dicts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

LAN_CONTROL_LIMITATION = (
    "Control test results are management information — not audit opinions or security verdicts."
)


class ControlOutcome(StrEnum):
    """LAN control test outcome labels.

    Variants:
        PASS: Evidence satisfies the control criteria.
        FAIL: Evidence contradicts the control criteria.
        PARTIAL: Evidence is incomplete or mixed.
        NOT_TESTED: Required evidence was not available.

    Side effects:
        None."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    NOT_TESTED = "NOT_TESTED"


@dataclass
class LanControlDefinition:
    """Canonical definition for one CTRL-LAN control in the registry.

    Attributes:
        control_id: Stable identifier (e.g. ``CTRL-LAN-001``).
        objective: Plain-English control objective statement.
        evidence_required: Evidence types that must exist for a meaningful test.
        test_procedure: How to evaluate the control against collected evidence.
        pass_criteria: Conditions that yield a PASS outcome.
        fail_criteria: Conditions that yield a FAIL outcome.
        risk_if_failed: Business risk when the control is not satisfied.
        remediation_recommendation: Suggested operator action (always prefixed
            ``"Consider (preview only):"`` — no autonomous remediation).
    """

    control_id: str
    objective: str
    evidence_required: list[str]
    test_procedure: str
    pass_criteria: str
    fail_criteria: str
    risk_if_failed: str
    remediation_recommendation: str


@dataclass
class LanControlTestResult:
    """Outcome of evaluating one CTRL-LAN control against collected evidence.

    Attributes:
        control_id: Stable identifier matching the ``LanControlDefinition`` entry.
        objective: Control objective echoed from the definition for audit readability.
        test_result: Outcome string: ``PASS``, ``FAIL``, ``PARTIAL``, or ``NOT_TESTED``.
        evidence: Human-readable evidence lines that informed this outcome.
        limitations: Scope caveats; always populated with ``LAN_CONTROL_LIMITATION``.
        recommendation: Suggested next step when test_result is FAIL or PARTIAL.
        risk_if_failed: Business risk when the control fails (echoed from definition).
    """

    control_id: str
    objective: str
    test_result: str
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    recommendation: str = ""
    risk_if_failed: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict for report and API output."""
        return asdict(self)


CONTROL_REGISTRY: list[LanControlDefinition] = [
    LanControlDefinition(
        control_id="CTRL-LAN-001",
        objective="Maintain asset inventory of LAN devices",
        evidence_required=["lan-inventory or DHCP import"],
        test_procedure="Verify device list exists with IP and MAC for known hosts.",
        pass_criteria="≥2 devices inventoried with identifiers.",
        fail_criteria="Empty inventory or no MAC/IP pairs.",
        risk_if_failed="Unknown devices may connect undetected.",
        remediation_recommendation="Consider (preview only): Run periodic lan-inventory and export baseline.",
    ),
    LanControlDefinition(
        control_id="CTRL-LAN-002",
        objective="Detect unauthorized devices",
        evidence_required=["inventory baseline", "DHCP or watch deltas"],
        test_procedure="Compare current inventory to baseline for new MAC/IP.",
        pass_criteria="No unauthorized new devices or documented approval.",
        fail_criteria="New unknown-vendor device without baseline entry.",
        risk_if_failed="Unmanaged device on production LAN.",
        remediation_recommendation="Consider (preview only): Review new device in router DHCP list.",
    ),
    LanControlDefinition(
        control_id="CTRL-LAN-003",
        objective="Review IoT outbound DNS activity",
        evidence_required=["router DNS log import"],
        test_procedure="Analyze DNS queries from IoT-like device IPs.",
        pass_criteria="DNS logs imported and reviewed for IoT clients.",
        fail_criteria="IoT devices present but no DNS evidence.",
        risk_if_failed="Outbound IoT traffic not visible.",
        remediation_recommendation="Consider (preview only): Enable router DNS logging.",
    ),
    LanControlDefinition(
        control_id="CTRL-LAN-004",
        objective="Segment IoT from work devices",
        evidence_required=["inventory vendor flags", "router VLAN evidence optional"],
        test_procedure="Check IoT-like and work-like devices on same segment indicators.",
        pass_criteria="Segmentation evidence or isolated guest network documented.",
        fail_criteria="IoT and work devices co-located without segmentation evidence.",
        risk_if_failed="Lateral movement risk between IoT and work assets.",
        remediation_recommendation="Consider (preview only): Enable guest Wi-Fi for IoT devices.",
    ),
    LanControlDefinition(
        control_id="CTRL-LAN-005",
        objective="Disable unnecessary discovery protocols",
        evidence_required=["mDNS/SSDP observation volume"],
        test_procedure="Measure discovery broadcast rate from non-essential devices.",
        pass_criteria="Discovery rate within normal SOHO bounds or documented.",
        fail_criteria="Excessive discovery from unknown sources.",
        risk_if_failed="Expanded attack surface via discovery protocols.",
        remediation_recommendation="Consider (preview only): Disable unused casting/discovery on IoT where supported.",
    ),
    LanControlDefinition(
        control_id="CTRL-LAN-006",
        objective="Review UPnP exposure",
        evidence_required=["SSDP/UPnP observations", "router config optional"],
        test_procedure="Check SSDP/UPnP activity and router UPnP setting if imported.",
        pass_criteria="UPnP reviewed or not observed on WAN path.",
        fail_criteria="UPnP observed without review evidence.",
        risk_if_failed="Unintended port mapping exposure.",
        remediation_recommendation="Consider (preview only): Disable UPnP on router if unnecessary.",
    ),
    LanControlDefinition(
        control_id="CTRL-LAN-007",
        objective="Retain router logs",
        evidence_required=["router DNS/firewall/DHCP import"],
        test_procedure="Verify router log import succeeded.",
        pass_criteria="≥1 router log type imported.",
        fail_criteria="No router evidence available.",
        risk_if_failed="Cannot correlate outbound or cross-host activity.",
        remediation_recommendation="Consider (preview only): Export and import router logs periodically.",
    ),
    LanControlDefinition(
        control_id="CTRL-LAN-008",
        objective="Investigate repeated subnet probing",
        evidence_required=["lan-watch observations", "firewall log optional"],
        test_procedure="Detect broad subnet probing or lateral recon classification.",
        pass_criteria="No broad probing or investigation documented.",
        fail_criteria="BROAD_SUBNET_PROBING or POSSIBLE_LATERAL_RECON without review.",
        risk_if_failed="Possible reconnaissance on LAN.",
        remediation_recommendation="Consider (preview only): Isolate probing device; collect router/pcap evidence.",
    ),
]


def run_lan_control_tests(
    *,
    inventory: dict[str, Any],
    observations: list[dict[str, Any]],
    router_events: list[dict[str, Any]],
    score_result: dict[str, Any] | None = None,
) -> list[LanControlTestResult]:
    """Evaluate all CTRL-LAN-001 through CTRL-LAN-008 controls against collected evidence.

    Args:
        inventory: LAN device inventory dict with a ``devices`` list; each device may
            contain ``flags`` (e.g. ``iot_like``, ``unknown_vendor``) and ``vendor`` fields.
        observations: Network observation dicts with ``protocol`` fields (e.g. ``MDNS``,
            ``SSDP``, ``UPNP``) from LAN watch or packet capture imports.
        router_events: Router log events (DNS, DHCP, firewall) imported via router import CLI.
        score_result: Optional LAN risk/classification scoring result; provides
            ``classification`` or ``primary_classification`` for CTRL-LAN-008 (subnet probing).

    Returns:
        List of ``LanControlTestResult`` objects in ``CONTROL_REGISTRY`` order (001–008).
        Each result includes ``test_result``, evidence lines, limitations, and recommendation.

    Side effects:
        None — pure evaluation over in-memory dicts.
    """
    devices = inventory.get("devices") or []
    score_result = score_result or {}
    classification = score_result.get("classification") or ""
    results: list[LanControlTestResult] = []

    for ctrl in CONTROL_REGISTRY:
        outcome = ControlOutcome.NOT_TESTED
        evidence: list[str] = []
        cid = ctrl.control_id

        if cid == "CTRL-LAN-001":
            if len(devices) >= 2:
                outcome = ControlOutcome.PASS
                evidence.append(f"{len(devices)} devices inventoried")
            elif devices:
                outcome = ControlOutcome.PARTIAL
                evidence.append("Sparse inventory")
            else:
                outcome = ControlOutcome.FAIL

        elif cid == "CTRL-LAN-002":
            unknown_new = [d for d in devices if "unknown_vendor" in (d.get("flags") or [])]
            if not unknown_new:
                outcome = ControlOutcome.PASS
            elif router_events:
                outcome = ControlOutcome.PARTIAL
                evidence.append("Unknown devices — router DHCP may clarify")
            else:
                outcome = ControlOutcome.FAIL
                evidence.append(f"{len(unknown_new)} unknown-vendor devices")

        elif cid == "CTRL-LAN-003":
            dns = [e for e in router_events if e.get("event_type") == "dns"]
            iot = [d for d in devices if "iot_like" in (d.get("flags") or [])]
            if dns and iot:
                outcome = ControlOutcome.PASS
                evidence.append(f"{len(dns)} DNS events for review")
            elif dns:
                outcome = ControlOutcome.PARTIAL
            elif iot:
                outcome = ControlOutcome.FAIL
                evidence.append("IoT present without DNS logs")
            else:
                outcome = ControlOutcome.NOT_TESTED

        elif cid == "CTRL-LAN-004":
            iot = [d for d in devices if "iot_like" in (d.get("flags") or [])]
            work = [
                d
                for d in devices
                if any(x in (d.get("vendor") or "").lower() for x in ("dell", "intel", "apple"))
            ]
            if iot and work:
                outcome = ControlOutcome.FAIL
                evidence.append("IoT and work devices on same inventory segment")
            elif iot or work:
                outcome = ControlOutcome.PARTIAL
            else:
                outcome = ControlOutcome.PASS

        elif cid == "CTRL-LAN-005":
            mdns_ssdp = sum(
                1 for o in observations if o.get("protocol") in {"MDNS", "SSDP", "UPNP"}
            )
            if mdns_ssdp > 20:
                outcome = ControlOutcome.PARTIAL
                evidence.append(f"High discovery volume: {mdns_ssdp}")
            elif mdns_ssdp:
                outcome = ControlOutcome.PASS
            else:
                outcome = ControlOutcome.NOT_TESTED

        elif cid == "CTRL-LAN-006":
            upnp = any(o.get("protocol") in {"SSDP", "UPNP"} for o in observations)
            if upnp:
                outcome = ControlOutcome.PARTIAL
                evidence.append("SSDP/UPnP observed — review recommended")
            else:
                outcome = ControlOutcome.PASS

        elif cid == "CTRL-LAN-007":
            if router_events:
                outcome = ControlOutcome.PASS
                evidence.append(f"{len(router_events)} router events imported")
            else:
                outcome = ControlOutcome.FAIL

        elif cid == "CTRL-LAN-008":
            primary = classification or score_result.get("primary_classification", "")
            if primary in {"BROAD_SUBNET_PROBING", "POSSIBLE_LATERAL_RECON"}:
                outcome = ControlOutcome.FAIL
                evidence.append(f"Classification: {primary}")
            elif observations:
                outcome = ControlOutcome.PASS
            else:
                outcome = ControlOutcome.NOT_TESTED

        results.append(
            LanControlTestResult(
                control_id=cid,
                objective=ctrl.objective,
                test_result=outcome.value,
                evidence=evidence,
                limitations=[LAN_CONTROL_LIMITATION],
                recommendation=ctrl.remediation_recommendation,
                risk_if_failed=ctrl.risk_if_failed,
            )
        )

    return results

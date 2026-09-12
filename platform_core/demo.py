"""Offline-safe platform demo: fixtures → JSONL → policy previews (no network repair)."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from platform_core.models import EndpointIdentity, EndpointSnapshot, FailureEvent
from platform_core.policy import build_preview, evaluate_action
from platform_core.storage import (
    append_failure_event,
    append_snapshot,
    list_metrics,
    record_audit,
    upsert_endpoint,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_fixture(name: str) -> dict:
    p = _repo_root() / "tests" / "fixtures" / "platform" / name
    return json.loads(p.read_text(encoding="utf-8"))


def run_demo() -> dict:
    """Load synthetic fixtures, write JSONL under a temp dir, exercise policy (no subprocess)."""
    prev_data = os.environ.get("PLATFORM_DATA_DIR")
    with tempfile.TemporaryDirectory() as td:
        os.environ["PLATFORM_DATA_DIR"] = td
        try:
            eid = "demo_endpoint_fixture_hash_deadbeef"
            hb = EndpointIdentity(
                endpoint_id=eid,
                os_family="Windows",
                os_version="fixture",
                agent_version="platform_core.demo",
            )
            upsert_endpoint(hb.model_dump())

            snap_blob = _load_fixture("endpoint_dns_failure.json")["snapshot"]
            ev_blob = _load_fixture("endpoint_dns_failure.json")["failure_event"]
            snap_blob["endpoint_id"] = eid
            ev_blob["endpoint_id"] = eid
            es = EndpointSnapshot.model_validate(snap_blob)
            fe = FailureEvent.model_validate(ev_blob)
            append_snapshot(es.model_dump())
            append_failure_event(fe.model_dump())

            dns_preview = build_preview(fe, "reset_dns", requested_surface="api")
            fw_preview = build_preview(
                fe.model_copy(update={"severity": "high"}),
                "reset_firewall",
                requested_surface="api",
            )
            arb = evaluate_action("arbitrary_command", "api")

            record_audit(
                {
                    "audit_id": "demo-audit-1",
                    "actor": "demo",
                    "action": "run_demo_complete",
                    "target_type": "platform",
                    "target_id": eid,
                    "decision": "informational",
                    "rationale": "fixture_only_no_repair",
                },
            )

            metrics = list_metrics()

            return {
                "dns_preview_allowed": dns_preview.allowed_by_policy,
                "firewall_preview_allowed": fw_preview.allowed_by_policy,
                "arbitrary_forbidden": not arb.allowed,
                "metrics_keys": sorted(metrics.keys()),
                "fixture_scenario": "endpoint_dns_failure",
            }
        finally:
            if prev_data is None:
                os.environ.pop("PLATFORM_DATA_DIR", None)
            else:
                os.environ["PLATFORM_DATA_DIR"] = prev_data


def main() -> int:
    """Run the command-line entry point.

    Returns:
        Process exit code or None when the command completes normally.

    Side effects:
        May perform the I/O or state updates implied by the operation.
    """
    out = run_demo()
    print(json.dumps(out, indent=2))
    assert out["dns_preview_allowed"] is True
    assert out["firewall_preview_allowed"] is False
    assert out["arbitrary_forbidden"] is True
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

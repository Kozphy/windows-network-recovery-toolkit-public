"""Endpoint evidence analytics pipeline tests."""

from __future__ import annotations

import json
from pathlib import Path

from windows_network_toolkit.analytics import (
    aggregate_control_results,
    aggregate_incidents_by_class,
    build_dashboard_dataset,
)
from windows_network_toolkit.analytics_pipeline import (
    export_endpoint_analytics,
    normalize_events_from_fixture,
    run_endpoint_analytics_pipeline,
)
from windows_network_toolkit.control_tests import (
    ControlTestOutcome,
    map_control_tests_from_incident,
)
from windows_network_toolkit.evidence_schema import (
    make_event_id,
    normalize_listener_state,
    normalize_probe_result,
    normalize_proxy_state,
)
from windows_network_toolkit.incident_classifier import classify_incident_from_events

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "analytics_pipeline_fixture.json"


def test_make_event_id_deterministic() -> None:
    a = make_event_id("2026-06-18T10:00:00Z", "proxy_state", {"enabled": True})
    b = make_event_id("2026-06-18T10:00:00Z", "proxy_state", {"enabled": True})
    c = make_event_id("2026-06-18T10:00:00Z", "proxy_state", {"enabled": False})
    assert a == b
    assert a != c


def test_evidence_event_serialization() -> None:
    ev = normalize_proxy_state(
        {"timestamp_utc": "2026-06-18T10:00:00Z", "wininet_proxy_enabled": True, "wininet_proxy_server": "127.0.0.1:1"},
    )
    payload = json.dumps(ev.to_dict(), sort_keys=True)
    assert "T1_STATE_EVIDENCE" in payload


def test_normalize_listener_and_probe() -> None:
    listener = normalize_listener_state({"timestamp_utc": "t", "listener_found": True, "process": {"name": "node.exe"}})
    probe = normalize_probe_result(
        {"timestamp_utc": "t", "health": {"proxy_status": "DIRECT_ONLY_WORKS", "direct_probe_ok": True, "proxy_probe_ok": False}},
    )
    assert listener.evidence_type == "listener_state"
    assert probe.normalized_fields["proxy_status"] == "DIRECT_ONLY_WORKS"
    assert probe.normalized_fields["proxy_probe_ok"] is False


def test_classify_dead_proxy_config() -> None:
    events = [
        normalize_proxy_state(
            {
                "timestamp_utc": "2026-06-18T10:00:00Z",
                "wininet_proxy_enabled": True,
                "wininet_proxy_server": "127.0.0.1:59081",
                "localhost_port": 59081,
            }
        ),
        normalize_listener_state({"timestamp_utc": "2026-06-18T10:00:01Z", "listener_found": False}),
    ]
    incident = classify_incident_from_events(events)
    assert incident.incident_class == "DEAD_PROXY_CONFIG"
    assert incident.risk_level == "HIGH"


def test_classify_direct_only_fixture() -> None:
    events = normalize_events_from_fixture(json.loads(FIXTURE.read_text(encoding="utf-8")))
    incident = classify_incident_from_events(events)
    assert incident.incident_class in ("DIRECT_ONLY_WORKS", "WININET_WINHTTP_MISMATCH", "REVERTER_SUSPECTED")
    controls = map_control_tests_from_incident(incident, events)
    assert len(controls) == 6


def test_control_mapping_partial_owner_without_writer_proof() -> None:
    events = normalize_events_from_fixture(json.loads(FIXTURE.read_text(encoding="utf-8")))
    incident = classify_incident_from_events(events)
    controls = map_control_tests_from_incident(incident, events)
    owner = next(c for c in controls if c.control_id == "WININET_PROXY_OWNER_VERIFICATION")
    assert owner.test_result == ControlTestOutcome.PARTIAL.value


def test_analytics_aggregation_shape() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload = run_endpoint_analytics_pipeline(fixture=data)
    dash = payload["dashboard_dataset"]
    assert dash["summary"]["total_evidence_events"] >= 3
    assert "incident_classes" in dash["charts"]


def test_dashboard_dataset_via_helpers() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    events = normalize_events_from_fixture(data)
    incident = classify_incident_from_events(events)
    controls = map_control_tests_from_incident(incident, events)
    dash = build_dashboard_dataset(events, [incident], controls)
    assert aggregate_incidents_by_class([incident])
    assert aggregate_control_results(controls)
    assert dash["charts"]["timeline"]


def test_csv_export(tmp_path: Path) -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload = run_endpoint_analytics_pipeline(fixture=data)
    paths = export_endpoint_analytics(payload, tmp_path, export_csv=True)
    assert (tmp_path / "dashboard_dataset.json").is_file()
    assert (tmp_path / "incident_classes.csv").is_file()
    assert "incident_classes.csv" in paths


def test_cli_analytics_summary_smoke() -> None:
    from io import StringIO
    from unittest.mock import patch

    from windows_network_toolkit import cli

    cap = StringIO()
    with patch("sys.stdout", cap):
        rc = cli.main(["analytics-summary", "--fixture", str(FIXTURE), "--json"])
    assert rc == 0
    out = json.loads(cap.getvalue())
    assert out["schema_version"] == "endpoint_evidence_analytics.v1"

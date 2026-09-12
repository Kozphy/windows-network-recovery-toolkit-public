# START HERE — Endpoint Reliability Decision Platform

## What this is

An **evidence-based Windows endpoint reliability and IT risk decision platform**. It collects endpoint signals, builds an incident timeline, ranks hypotheses, applies **policy-gated** remediation previews, and exports **audit-ready** reports.

Windows endpoints often fail while still appearing online (proxy errors, dead localhost ports, WinINET/WinHTTP drift).

A **LAN privacy module** adds home/SOHO device inventory, router log import, privacy risk scoring, and CTRL-LAN controls — observation only, not confirmed surveillance. See [lan-privacy-monitor.md](lan-privacy-monitor.md).

**Pipeline:** Evidence → Hypothesis → Proof → Policy → Remediation → Audit → Replay

## What this is not

- Not an AI agent (no autonomous remediation)
- Not a silent repair tool (no registry/process/firewall changes without typed confirmation)
- Not a certainty engine (confidence is ordinal, not probability)
- Not formal SOC2 certification (governance mapping is informational)

## Safety guarantees

| Principle | Enforced |
|-----------|----------|
| Observation ≠ Proof | Evidence tier state machine |
| Correlation ≠ Causation | Guards block destructive unlock |
| Confidence ≠ Certainty | Ordinal scores only |
| Policy permission ≠ safety guarantee | Approval + rollback required |

Destructive actions (registry, kill process, firewall reset, adapter disable) require preview, typed confirmation, audit, and rollback plan. API execute defaults to `dry_run=true`.

## 5-minute demo

```powershell
pip install -e ".[dev]"
$env:PYTHONPATH = (Get-Location).Path
make demo
```

See [demo_5_min.md](demo_5_min.md) for expected output.

## Architecture (canonical core)

| Package | Role |
|---------|------|
| **`src/platform_core/`** | Canonical decision engine (evidence, policy, audit chain, replay) |
| **`windows_network_toolkit/`** | Windows portfolio CLI, collectors, reports, `/platform/*` API |
| **`src/proxy_guard/`** | Live Windows proxy probes and remediation previews |
| **`backend/`** | FastAPI — `/v1/*` canonical + legacy `/platform/*` |
| **`platform_core/`** (root) | Legacy ops (fleet, SRE, remediation registry) — shim to canonical where possible |
| **`labs/`** | Experimental — not mainline |

Full map: [architecture.md](architecture.md)

## Mainline vs labs

- **Mainline:** `src/platform_core`, `windows_network_toolkit`, `backend/canonical_routes.py`, `tests/platform_core`
- **Labs:** `labs/`, `backend/decision_intelligence/`, `platform_core/outcome_learning/` — portfolio demos only

## Key commands

```powershell
make demo                              # Golden fixture replay + report
python -m toolkit replay proxy_drift_incident.jsonl
python -m windows_network_toolkit bad-gateway-diagnose --url https://example.com
python -m toolkit audit verify logs/canonical_decision_audit.jsonl
pip install -e ".[dashboard]"          # optional local monitoring UI
python -m windows_network_toolkit dashboard   # http://127.0.0.1:8765 (read-only)
pytest -q
```

## Reading order

1. [DOCUMENTATION_INDEX.md](DOCUMENTATION_INDEX.md) — full layered index (demos, portfolio, LAN, production depth)
2. [portfolio-positioning.md](portfolio-positioning.md) — audience guides and interview packs
3. [epistemic_model.md](epistemic_model.md)
4. [architecture/canonical_decision_pipeline.md](architecture/canonical_decision_pipeline.md)
5. [safety_doctrine.md](safety_doctrine.md)
6. [bad_gateway_diagnostic.md](bad_gateway_diagnostic.md)
7. [monitoring-dashboard.md](monitoring-dashboard.md) — local read-only NiceGUI evidence UI

Extended demos: [demo-commands-reference.md](demo-commands-reference.md) · Incidents: [incident-walkthrough-dead-proxy.md](incident-walkthrough-dead-proxy.md)

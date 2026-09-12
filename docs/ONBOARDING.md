# Onboarding — 10-minute repository map

**What this is:** A Technology Risk & Control Analytics toolkit for Windows endpoint proxy
reliability. It collects evidence, classifies incidents, runs control tests, scores risk,
previews remediation, and writes audit-ready reports.

**What this is not:** Antivirus, EDR/XDR, malware detection, or autonomous remediation.

**Documentation standards:** [code-documentation-standards.md](code-documentation-standards.md)

---

## Core flow (read top to bottom)

```text
Evidence → Classification → Control tests → Risk scoring → Human review → Audit → Report
```

| Stage | Primary module | CLI / API |
|-------|----------------|-----------|
| Evidence | `evidence_schema.py`, `proxy_state.py`, `proxy_health.py` | `proxy-status`, `proxy-health` |
| Classification | `incident_classifier.py` | (inside `analytics-summary`) |
| Control tests | `control_tests.py` | `control-test`, `GET /controls` |
| Risk scoring | `risk_scoring_engine.py` | `GET /risks` |
| Reporting | `reporting.py`, `analytics_pipeline.py` | `analytics-export`, `GET /reports/executive` |
| Latest snapshot | `latest_evidence_report.py` | `evidence-report --latest` |
| Remediation preview | `proxy_remediation.py` | `proxy-disable` (dry-run default) |
| IPv6 path / prefer-IPv4 | `ipv6_path.py` | `ipv6-path`, `ipv6-path-status`, `ipv6-prefer-ipv4`, `ipv6-restore-preference` |
| DNS / Edge name resolve | `dns_edge.py` | `dns-edge-status`, `dns-edge-fix` |
| ChatGPT app-path | `src/network_recovery/` | `diagnose --app chatgpt`, `auto-fix-chatgpt`, `make fix-chatgpt` |
| Read-only agent | `windows_network_toolkit/agent/` | `agent once`, `agent run`, `agent health`, `agent spool-status` |
| LAN privacy | `windows_network_toolkit/diagnostics/lan_privacy/` | `lan-inventory`, `lan-watch`, `lan-privacy-report` |
| AI evals | `src/platform_core/ai_evals/` | `ai-eval` (fixture-only) |
| Startup observability | `src/proxy_drift/` | `install-startup-observability`, `collect-evidence-bundle`, `proxy-boot-trace` |

---

## Repository layout

```text
windows_network_toolkit/   # Primary CLI package (python -m windows_network_toolkit)
src/proxy_drift/           # Startup observability, boot trace, guardian, evidence bundle
src/cli.py                 # Extended operator CLI (python -m src)
src/platform_core/         # Canonical governance, proof, audit, case-study risk
src/proxy_guard/           # Legacy proxy-watch integration
backend/                   # FastAPI host (optional local demo API)
frontend/                  # Optional Next.js dashboards
tests/                     # Pytest contracts and fixtures
docs/                      # Architecture, risk model, demo script
examples/reports/          # Sample executive export artefacts
```

---

## Safety boundaries (non-negotiable)

1. Observation is not proof.
2. Correlation is not causation.
3. Classification is not accusation.
4. Policy permission is not a safety guarantee.
5. Dry-run is default for registry-changing commands.
6. No silent process kill, firewall reset, or adapter disable.

See `windows_network_toolkit/safety.py` and `SECURITY.md`.

---

## CLI command map (high level)

Full argparse definitions live in `windows_network_toolkit/cli.py`.

| Group | Commands |
|-------|----------|
| Evidence | `proxy-status`, `proxy-health`, `proxy-watch`, `proxy-owner`, `diagnose`, `evidence-report` |
| Proof | `proxy-proof`, `tls-proof`, `proxy-writer-attribution` |
| Remediation | `proxy-disable`, `ipv6-prefer-ipv4`, `ipv6-restore-preference`, `dns-edge-fix` (dry-run default); `ipv6-path` / `ipv6-path-status` / `dns-edge-status` (read-only) |
| Analytics | `analytics-summary`, `analytics-export`, `powerbi-export` |
| Governance | `risk-assess`, `control-test`, `governance-report`, `risk-kpi-summary` |
| LAN privacy | `lan-inventory`, `lan-watch`, `lan-privacy-report`, `lan-risk-score`, `lan-control-test` |
| AI evals | `ai-eval` (fixture-only, no live model calls) |
| Startup observability | `install-startup-observability`, `collect-evidence-bundle`, `startup-observability-report`, `proxy-boot-trace` (`python -m src`) |
| Audit | `audit verify` |

---

## First commands (fixture-safe, any OS)

```powershell
pip install -e ".[dev]"
$env:PYTHONPATH = (Get-Location).Path

python -m windows_network_toolkit analytics-summary `
  --fixture tests/fixtures/analytics_pipeline_fixture.json --json

python -m windows_network_toolkit evidence-report --analytics `
  --fixture tests/fixtures/analytics_pipeline_fixture.json

python -m pytest -q
```

---

## API (optional)

```powershell
uvicorn backend.main:app --reload
```

| Route | Purpose |
|-------|---------|
| `GET /trisk/health` | Technology risk API health |
| `GET /incidents` | Classified incidents |
| `GET /risks` | Risk scores |
| `GET /controls` | Control tests + catalog |
| `GET /reports/executive` | Executive JSON report |

Root `GET /health` serves the ERP platform router — not the technology risk API.

---

## Where to read next

- [architecture.md](architecture.md) — layered design
- [chatgpt-auto-fix.md](chatgpt-auto-fix.md) — ChatGPT connectivity auto-fix
- [agent-deployment.md](agent-deployment.md) — Read-only local endpoint agent
- [lan-privacy-monitor.md](lan-privacy-monitor.md) — LAN privacy CLI
- [ai-evals-feedback-loop.md](ai-evals-feedback-loop.md) — AI evals harness
- [risk-model.md](risk-model.md) — scoring inputs/outputs
- [powerbi-schema.md](powerbi-schema.md) — CSV/star schema export
- [demo-script.md](demo-script.md) — 3-minute portfolio walkthrough
- [README.md](../README.md) — full command reference

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Empty analytics | Audit dir empty — use `--fixture` or run `proxy-watch` |
| HIGH risk but low proof | Expected with T0/T1 — read `limitations[]` |
| API 403 on fixture | Path must be under `tests/fixtures` or `examples` |
| Tests fail on Windows-only probes | Use fixture inject paths in CI |

---

## Audit notes for reviewers

- Verify hash-chained JSONL with `audit verify`.
- Compare API/CLI output schema versions before dashboard ingestion.
- Do not strip `limitations` from committee reports.

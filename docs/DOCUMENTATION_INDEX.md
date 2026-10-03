# Documentation Index

10-minute orientation for engineers and auditors. All paths are relative to the repository root.

## What this repository is

A **local-first Windows endpoint reliability toolkit** with a growing **Decision Intelligence Platform**:

- **Primary CLI:** JSON-first diagnostics and policy-gated remediation (`python -m windows_network_toolkit`)
- **Extended Windows operator CLI:** `python -m src` (startup observability, proxy drift, network-state, platform handlers)
- Append-only JSONL audit trails (`.audit/` + legacy `logs/`) and deterministic replay
- FastAPI platform API (`backend/`) with optional PostgreSQL
- Multi-domain adapters (Windows, Security, Cloud, Infrastructure, Market Events)
- Research-only market catalyst monitoring (no trade execution)

## Portfolio pack (recruiters, Big 4, FAANG, PL-300)

| Doc | Purpose |
|-----|---------|
| **[README.md](../README.md)** | **30-second positioning + non-claims (start here)** |
| [production-readiness-gap.md](production-readiness-gap.md) | Honest production gap table (updated with Level-1 domain event kernel) |
| [domain-event-kernel.md](domain-event-kernel.md) | Canonical `wnrt.domain_event.v1` envelope, writer, verify demo |
| [domain-event-inventory.md](domain-event-inventory.md) | Pre-kernel JSONL inventory and migration risks |
| [threat-model.md](threat-model.md) | 10 abuse scenarios + test mapping |
| [docker-demo.md](docker-demo.md) | Reviewer Docker Demo (Option C) |
| [../real_evidence/case-001-dead-proxy/](../real_evidence/case-001-dead-proxy/) | Sanitized evidence case pack |
| [architecture-infographic.md](architecture-infographic.md) | Mermaid evidence pipeline |
| [interview-demo-3min.md](interview-demo-3min.md) | FAANG / Big 4 / mixed panel demo paths |
| [one-page-case-study-dead-proxy.md](one-page-case-study-dead-proxy.md) | Dead proxy case study |
| [replay-demo.md](replay-demo.md) | Deterministic proxy replay |
| [test-strategy.md](test-strategy.md) | Fixtures, safety contracts, tamper detection |
| [faang-platform-review.md](faang-platform-review.md) | Platform / SRE reviewer pack |
| [state-machine.md](state-machine.md) | Proxy transition state diagram |
| [api-trisk-examples.md](api-trisk-examples.md) | FastAPI read-only `/trisk/*` examples |
| [adr/ADR-portfolio-positioning.md](adr/ADR-portfolio-positioning.md) | Evidence pipeline ADR |
| [big4-interview-defense.md](big4-interview-defense.md) | Technology risk / audit defense |
| [control-matrix.md](control-matrix.md) | CTRL-001–010 with failure interpretation |
| [risk_register.md](risk_register.md) | Risk register with controls & limitations |
| [powerbi-interview-story.md](powerbi-interview-story.md) | PL-300 skill mapping |
| [../reports/sample_governance_report.md](../reports/sample_governance_report.md) | Sample management governance report |
| [../analytics/powerbi/report_blueprint.md](../analytics/powerbi/report_blueprint.md) | Power BI four-page blueprint |

## Portfolio pack (legacy index)

| Doc | Purpose |
|-----|---------|
| **[README_BIG4_PORTFOLIO.md](README_BIG4_PORTFOLIO.md)** | **Big 4 / Risk Advisory portfolio index** |
| [big4_interview_positioning.md](big4_interview_positioning.md) | Core Big 4 framing and STAR story |
| [technology_risk_control_matrix.md](technology_risk_control_matrix.md) | Control testing matrix |
| [interview_pitch_90_seconds.md](interview_pitch_90_seconds.md) | 90-second spoken pitch |
| [interview_pitch_5_minutes.md](interview_pitch_5_minutes.md) | 5-minute detailed pitch |
| [big4_demo_flow.md](big4_demo_flow.md) | Live interview demo script |
| [big4_interviewer_q_and_a.md](big4_interviewer_q_and_a.md) | Anticipated Q&A |
| [resume_bullets_big4.md](resume_bullets_big4.md) | Resume bullets (Risk / Consulting / FinTech) |
| [consulting_case_study.md](consulting_case_study.md) | STAR consulting case study |
| [fintech_operational_risk_case.md](fintech_operational_risk_case.md) | FinTech operational resilience angle |
| [linkedin_big4_portfolio_post.md](linkedin_big4_portfolio_post.md) | LinkedIn announcement draft |
| [control-matrix.md](control-matrix.md) | Portfolio control matrix summary |
| [sql_analytics_queries.md](sql_analytics_queries.md) | **12+ KPI SQL queries with interpretation** |
| [portfolio-summary.md](portfolio-summary.md) | General portfolio summary |
| [case-study-1-proxy-drift.md](case-study-1-proxy-drift.md) | Dead proxy drift case study |
| [case-study-2-unknown-local-proxy-listener.md](case-study-2-unknown-local-proxy-listener.md) | Unknown listener case study |
| [case-study-3-endpoint-reliability-decision-engine.md](case-study-3-endpoint-reliability-decision-engine.md) | Decision engine case study |
| [consulting-report.md](consulting-report.md) | Manager-facing risk assessment |
| [demo-video-script.md](demo-video-script.md) | 3–5 minute demo script |
| [ai_investigation_platform_architecture.md](ai_investigation_platform_architecture.md) | AI-assisted investigation platform design |
| [architecture/supabase_fleet_schema_sketch.md](architecture/supabase_fleet_schema_sketch.md) | Minimal Supabase fleet tables (preview-only; safety-preserving) |
| [runbooks/edge-extensions-policy.md](runbooks/edge-extensions-policy.md) | Gated Edge extension block/restore (AdGuard/UA preset) |
| [rag_investigation_design.md](rag_investigation_design.md) | RAG retrieval system (SQLite → pgvector) |
| [hypothesis_engine_design.md](hypothesis_engine_design.md) | Multievidence hypothesis engine |
| [decision_intelligence_platform_design.md](decision_intelligence_platform_design.md) | Federated 5-domain DIP (IT, Security, Risk, Business, Compliance) |
| [screenshots/README.md](screenshots/README.md) | Screenshot placeholders |

## Golden case (59081)

Dead WinINET localhost proxy — see [case-studies/dead-localhost-proxy.md](case-studies/dead-localhost-proxy.md).

```powershell
python -m windows_network_toolkit proxy-status --fixture tests/fixtures/enert/dead_proxy_59081.json
python -m windows_network_toolkit diagnose --proof --fixture tests/fixtures/enert/dead_proxy_59081.json
```

## Core flows

### Documentation conventions and audit boundaries

Implementation contracts are documented at the critical-path modules rather
than inferred from route names alone:

- `backend/services/audit_service.py` — tenant-scoped database audit rows and
  chain verification.
- `backend/services/evidence_service.py` — observation/evidence separation,
  stable evidence identity, limitations, and tenant filtering.
- `src/platform_core/audit/` — canonical JSONL custody, tip anchors, and
  verification limits.
- `docs/code-documentation-standards.md` — language-specific style and
  evidence-based wording rules.

When investigating a report, preserve the raw snapshot, evidence tier,
limitations, correlation ID, and relevant audit record before rerunning a
collector. A successful hash or content check demonstrates consistency, not
causality or truth of the underlying observation.

### 1. Windows endpoint reliability (final causation)

```text
proxy-watch (drift) → registry_writer_proof + port_owner + process_tree + proxy_path_proof → final_causation verdict
```

Commands:

```powershell
python -m src proxy-watch --final-causation
python -m src proxy-causation --since-minutes 30 --format markdown
python -m src proxy-causation --fixture tests/fixtures/proxy_causation/scenario1_proven_writer_port_owner
```

Modules: `src/proxy_guard/registry_writer_proof.py`, `final_causation.py`, `port_owner.py`, `process_tree.py`, `proxy_path_proof.py`

### 1b. Localhost web-app refuse-to-connect

```text
localhost-diagnose → TCP/listener/process/HTTP/proxy evidence → classification + T0–T5 → PREVIEW remediation
```

```powershell
python -m windows_network_toolkit localhost-diagnose --url "http://localhost:61161/ChtPopupForm" --json --remediation-preview
```

Docs: [localhost-diagnose.md](localhost-diagnose.md)

### 1c. Browser profile differential (normal vs InPrivate)

```text
raw OS/protocol probe → HAR / controlled probe / profile metadata → classify → repair-preview (PREVIEW default)
```

```powershell
python -m windows_network_toolkit browser-diff https://www.104.com.tw/ --fixture tests/fixtures/browser_profile/104_profile_fail.json --format text
python -m windows_network_toolkit browser-diff https://example.com/ --browser edge --import-normal-har normal.har --import-private-har private.har --proof
python -m windows_network_toolkit browser-profile repair-preview 104.com.tw --browser edge
```

Docs: [browser-profile-differential.md](browser-profile-differential.md) · [har-redaction.md](har-redaction.md) · [browser-repair-safety.md](browser-repair-safety.md) · [browser-evidence-model.md](browser-evidence-model.md)

### 1d. Decision context (stakeholder + timing)

```text
Proof/policy (unchanged) → stakeholder resolve → timing evaluate → coordination status → preview
```

```powershell
python -m windows_network_toolkit diagnose --proof --decision-context --fixture tests/fixtures/enert/dead_proxy_59081.json
python -m windows_network_toolkit stakeholder-resolve --case-id CASE --classification DEAD_PROXY_CONFIG
python -m windows_network_toolkit timing-evaluate --case-id CASE --timezone Asia/Taipei
python -m windows_network_toolkit decision-explain --case-id CASE --format text
```

Docs: [decision-context.md](decision-context.md)

### 2. Multi-domain decision platform (fixture-based)

```text
NormalizedEvent → Evidence → Hypotheses → Decisions → Policy → Audit → Replay → Metrics
```

Commands:

```powershell
python -m src platform events
python -m src platform decide --event-id win-proxy-localhost-001
python -m src platform replay
```

Modules: `src/core/`, `src/domains/`, `src/platform_handlers.py` · Doc: [multi_domain_decision_platform.md](multi_domain_decision_platform.md) · Tests: `tests/test_multi_domain_platform.py`

### 3. Windows endpoint reliability (classic)

```text
Signals → FailureBlocks → Hypothesis/Evidence → Policy (ALLOW/PREVIEW/BLOCK) → Preview (dry-run default)
```

Entry: `src/cli.py` · Tests: `tests/test_policy_safety_contract.py`, `tests/test_replay_determinism.py`

### 4. ChatGPT auto-fix (Windows, policy-gated)

```text
auto-fix-proxy → bad-gateway-diagnose → chatgpt scenario diagnose → LOW-risk apply (APPLY_CHATGPT_LOW_RISK)
```

Commands:

```powershell
make fix-chatgpt
.\scripts\auto-fix-chatgpt.ps1
python -m windows_network_toolkit auto-fix-chatgpt --dry-run true
python -m src diagnose --app chatgpt --json
```

Modules: `src/network_recovery/`, `scripts/auto-fix-chatgpt.ps1` · Doc: [chatgpt-auto-fix.md](chatgpt-auto-fix.md) · Tests: `tests/test_network_recovery_auto_fix.py`

### 5. LAN privacy monitor (read-only)

```text
lan-inventory → lan-watch (JSONL) → lan-privacy-report / lan-risk-score → risk-executive-report
```

Commands:

```powershell
python -m windows_network_toolkit lan-inventory --fixture examples/lan/executive_bundle.json
python -m windows_network_toolkit lan-watch --duration 60 --audit-path .audit/lan-watch.jsonl
python -m windows_network_toolkit lan-privacy-report --fixture executive_bundle.json --format both
```

Modules: `windows_network_toolkit/diagnostics/lan_privacy/` · Doc: [lan-privacy-monitor.md](lan-privacy-monitor.md)

### 6. AI evals feedback loop (fixture-only)

```text
EvalCase fixtures → deterministic checks → failure taxonomy → policy gate → governance report
```

Commands:

```powershell
python -m windows_network_toolkit ai-eval --cases examples/ai_evals/support_bot_cases.json --format markdown
python -m windows_network_toolkit ai-eval --format json
```

Modules: `src/platform_core/ai_evals/` · Doc: [ai-evals-feedback-loop.md](ai-evals-feedback-loop.md) · Tests: `tests/ai_evals/`

### 7. Startup observability & proxy drift (Windows)

```text
install-startup-observability → guardian + boot trace (task or Startup hook fallback) → JSONL logs → collect-evidence-bundle → startup-observability-report
```

Commands:

```powershell
python -m src install-startup-observability
python -m src collect-evidence-bundle
python -m src startup-observability-report --json
python -m src proxy-boot-trace --duration 180 --interval 2
```

Modules: `src/proxy_drift/` · Docs: [startup-observability.md](startup-observability.md), [dead-proxy-guardian.md](dead-proxy-guardian.md) · Tests: `tests/test_proxy_drift_toolkit.py`

### 8. Shared decision engine

```text
EvidenceItem[] + CandidateDecision[] → score → rank → content_digest
```

Entry: `src/decision_engine/decision_engine.py` · Tests: `tests/decision_engine/`

### 9. Multi-domain platform

```text
AdapterContext → collect_observations → derive_evidence → run_shared_reasoning → DomainPipelineResult
```

Entry: `platform_core/decision_platform/` · Diagram: `docs/decision_platform_architecture.md` · Tests: `tests/decision_platform/`

### 10. Decision Intelligence API

```text
POST /decision-intelligence/{events|evidence|decisions|outcomes} → store (JSONL or PostgreSQL)
GET /decision-intelligence/metrics · POST /decision-intelligence/replay
```

Entry: `backend/decision_intelligence/routes.py` · Schema: `platform_core/db/decision_intelligence_schema.sql`

### 11. Outcome learning

```text
DecisionOutcome → evaluate → LearningMetrics → replay digest
```

Entry: `platform_core/outcome_learning/` · Fixture: `fixtures/outcome_learning/outcomes.json`

## Safety boundaries (non-negotiable)

| Boundary | Enforcement |
|----------|-------------|
| No silent remediation | Policy gates + dry-run defaults on API previews |
| Observation ≠ proof | Documented in adapters and market events module |
| Research ≠ execution | Market module blocks trade execution paths |
| Replayable decisions | SHA-256 `content_digest` / `engine_digest` on scoring paths |
| RBAC on API writes | `backend/platform_auth.py` + `platform_core/rbac.py` |

## Module map

| Path | Responsibility |
|------|----------------|
| `src/` | Extended Windows CLI (`python -m src`), collectors, market events CLI |
| `src/proxy_drift/` | Startup observability, boot trace, guardian, evidence bundle, safe search |
| `src/network_recovery/` | ChatGPT app-path scenario diagnose, LOW-risk auto-fix orchestrator |
| `windows_network_toolkit/diagnostics/lan_privacy/` | LAN inventory, watch, privacy report (read-only) |
| `src/platform_core/ai_evals/` | Fixture-based AI eval harness (`ai-eval` CLI) |
| `platform_core/` | Shared models, policy, SRE, decision platform, outcome learning |
| `src/decision_engine/` | Deterministic scoring and ranking |
| `src/knowledge/` | Versioned YAML facts (separate from code) |
| `backend/` | FastAPI routes, auth, metrics |
| `knowledge/` | Bundled YAML knowledge files |
| `fixtures/` | Deterministic test and demo inputs |
| `deploy/` | Prometheus/Grafana provisioning |

## Running tests

```powershell
$env:PYTHONPATH = (Get-Location).Path
pytest -q
```

Pytest uses `--import-mode=importlib` and `--basetemp=.pytest_tmp` (see `pytest.ini`) to avoid duplicate test module name collisions and keep temp artifacts under the repo instead of system `%TEMP%`.

Focused proxy drift tests:

```powershell
pytest -q tests/test_proxy_drift_toolkit.py --basetemp=.pytest_tmp
```

## Related docs

| Doc | Topic |
|-----|-------|
| `docs/case-studies/dead-localhost-proxy.md` | Golden 59081 dead proxy case |
| `docs/classification-model.md` | 12 primary labels + secondary signals |
| `docs/proof-vs-observation.md` | Proof envelope vs observation |
| `docs/interview-case-study.md` | Portfolio STAR narrative |
| `docs/three-minute-demo-script.md` | 3-minute fixture demo |
| `docs/big4-cyber-risk-positioning.md` | Cyber risk / audit framing (legacy — see README_BIG4_PORTFOLIO) |
| `docs/faang-platform-engineering-positioning.md` | Platform engineering framing |
| `docs/evidence_model.md` | Canonical evidence levels |
| `docs/policy_model.md` | Canonical policy decisions |
| `docs/observability.md` | Metrics and dashboard |
| `docs/demo_5_min.md` | 5-minute portfolio demo |
| `labs/README.md` | Experimental modules (not mainline) |
| `docs/decision_platform_architecture.md` | Multi-domain architecture diagram |
| `docs/decision_platform_migration.md` | Phased adapter/API wiring plan |
| `docs/production_shape_upgrade.md` | Production-shape portfolio upgrade |
| `docs/demo_production_5_min.md` | 5-minute production demo |
| `docs/sre_interview_walkthrough.md` | SRE portfolio narrative |
| `docs/security_tooling_walkthrough.md` | Security / forensics narrative |
| `docs/platform_engineering_walkthrough.md` | Platform engineering narrative |
| `docs/production_readiness.md` | Deployment and readiness checklist |
| `docs/test_strategy.md` | Safety regression strategy |
| `docs/platform_engineering_gap_report.md` | README vs repo reality audit |
| `docs/proxy_green_definition.md` | Proxy health definition |
| `docs/chatgpt-auto-fix.md` | ChatGPT auto-fix flow, tokens, audit paths |
| `docs/lan-privacy-monitor.md` | LAN privacy monitor CLI |
| `docs/ai-evals-feedback-loop.md` | AI evals fixture harness (`ai-eval`) |
| [enterprise-hardening-roadmap.md](enterprise-hardening-roadmap.md) | Production-shaped hardening program (8 phases) |
| [adr/ADR-enterprise-hardening-roadmap.md](adr/ADR-enterprise-hardening-roadmap.md) | ADR: agent, observability, cross-platform foundation |
| [agent-deployment.md](agent-deployment.md) | Read-only `wnrt agent *` CLI |
| [observability.md](observability.md) | trace_id, audit_id, structured JSON logs |
| [scale-testing.md](scale-testing.md) | Synthetic 100/1k/10k — local limits |
| [cross-platform-support.md](cross-platform-support.md) | Linux/macOS PARTIAL evidence |
| [packaging-installer.md](packaging-installer.md) | pipx/wheel/portable install plan |
| [security-review.md](security-review.md) | Threat model + abuse-case pack |
| [rollback-strategy.md](rollback-strategy.md) | Preview-first rollback six-part model |
| [startup-observability.md](startup-observability.md) | v0.3.0 startup observability architecture and CLI |
| [private-public-split.md](private-public-split.md) | Private monorepo vs public CLI/demo mirror export |
| [localhost-diagnose.md](localhost-diagnose.md) | Localhost ERR_CONNECTION_REFUSED evidence pipeline |
| [dead-proxy-guardian.md](dead-proxy-guardian.md) | Dead localhost WinINET proxy recovery runbook |
| [runbooks/ipv6-path-blackhole.md](runbooks/ipv6-path-blackhole.md) | IPv6 blackhole diagnose + prefer-IPv4 remediation |
| [runbooks/dns-edge-err-name-not-resolved.md](runbooks/dns-edge-err-name-not-resolved.md) | DNS/Edge ERR_NAME_NOT_RESOLVED diagnose + fix |
| [runbooks/why-broken.md](runbooks/why-broken.md) | Unified proxy vs DNS vs IPv6 why-broken investigate |
| [runbooks/edge-loading-triage.md](runbooks/edge-loading-triage.md) | Edge won't load / slow: one-shot `edge-triage` with token fix ladder |
| [runbooks/browser-blank-screen.md](runbooks/browser-blank-screen.md) | Edge blank/black UI (LinkedIn GPU/cache) diagnose + fix |
| [domain-provenance.md](domain-provenance.md) | Domain operator vs infrastructure geography (read-only) |
| [email_bec_detection.md](email_bec_detection.md) | Deterministic email / BEC risk detection (analysis-only, `email-risk`) |
| [runbooks/classification-outbox-stuck.md](runbooks/classification-outbox-stuck.md) | Stuck classification outbox pending recovery |
| [ops/slo-classification-outbox.md](ops/slo-classification-outbox.md) | Classification outbox SLO targets (non-attested) |
| [ops/failure-drill-classification-outbox.md](ops/failure-drill-classification-outbox.md) | Outbox dispatch-disabled failure drill postmortem |
| [yc-p0-productization-audit.md](yc-p0-productization-audit.md) | YC/P0 product control-plane audit |
| [openclaw-coding-agent.md](openclaw-coding-agent.md) | Policy-gated OpenClaw coding agent (draft PR only) |
| [audit-custody.md](audit-custody.md) | Level 1 hash-chained custody + tip; domain event dual-write |
| [procmon_proxy_filter.md](procmon_proxy_filter.md) | Procmon RegSetValue filter set + CSV import |
| [monitoring-dashboard.md](monitoring-dashboard.md) | Read-only NiceGUI local monitoring dashboard |
| [cli_reference.md](cli_reference.md) | Full `python -m src` command inventory |

## Audit checklist

1. Verify `content_digest` / `engine_digest` unchanged after scoring changes (`pytest tests/decision_engine`).
2. Confirm API mutations require RBAC headers (`tests/test_decision_intelligence_api.py`).
3. Confirm CLI fixture demos pass in CI (`ci.yml` smoke step).
4. Review append-only stores under `PLATFORM_DATA_DIR` for tamper evidence.

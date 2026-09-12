# 3-minute demo path

Deterministic, **no Administrator** required for the main flow. Works from a clean clone on Windows, macOS, or Linux (CLI fixture path); API steps use localhost only.

**Prerequisites**

```powershell
cd Windows-Network-Recovery-Toolkit
pip install -e ".[dev]"
$env:PYTHONPATH = (Get-Location).Path
```

---

## 0. System story (15 seconds)

```text
Observation → Event → State transition → Hypothesis → Optional proof
  → Policy (ALLOW / PREVIEW / BLOCK) → Preview → Audit → Replay → Dashboard
```

---

## 1. Read-only diagnosis from fixture (~30s)

```powershell
python -m src diagnose --fixture tests/fixtures/features_healthy_signals.json
Get-Content reports/last_diagnosis.json | Select-Object -First 30
```

Proxy drift scenario:

```powershell
python -m src diagnose --fixture tests/fixtures/features_proxy_issue.json
# Scenario catalog: demo_data/manifest.json
```

---

## 2. Live diagnosis (optional, read-only probes) (~30s)

On Windows only; still no registry mutation:

```powershell
python -m src diagnose-live --json
# Inspect run id in logs/decision_runs.jsonl (last line)
```

If non-Windows, skip and use fixture path above.

---

## 3. Proof-enabled diagnosis (fixture-safe) (~20s)

Reasoning engine with **CONFIRMED** proof contrast (pure Python, no Sysmon):

```powershell
python -c "from platform_core.reasoning_engine import observation, run_reasoning; from platform_core.reasoning_models import ProofResult; from platform_core.diagnosis_text import render_reasoning_summary; import json; o=[observation('ping_ok'),observation('browser_https_failed'),observation('wininet_proxy_enabled'),observation('proxy_bypass_succeeded'),observation('proxied_path_failed')]; r=run_reasoning(o, proof_result=ProofResult(hypothesis='browser_proxy_path_regression',status='CONFIRMED',checks_run=['proxy_bypass_contrast'])); print(json.dumps(render_reasoning_summary(r), indent=2))"
```

---

## 4. Generate audit JSONL (~15s)

Fixture diagnose appends legacy audit:

```powershell
python -m src diagnose --fixture tests/fixtures/features_dns_issue.json --repo-root (Join-Path $env:TEMP "wrt-demo")
Get-Content (Join-Path $env:TEMP "wrt-demo/logs/decision_audit.jsonl") -Tail 1
```

Platform audit (via API preview in step 7) writes `platform_data/audit.jsonl` when backend runs.

---

## 5. Replay a run_id (~20s)

**CLI live replay** (from `diagnose-live` on Windows):

```powershell
# After diagnose-live, take run_id from decision_runs.jsonl:
python -m src replay-live <run_id>
```

**Platform API replay** (works everywhere with stored diagnosis):

```powershell
# Terminal 1 — start backend (step 6), then:
curl -s -H "X-Operator-Role: admin" http://127.0.0.1:8000/platform/replay/<run_id>
```

**Inline policy replay** (no host probes):

```powershell
python -m platform_core.replay.runner --input tests/fixtures/platform/healthy_network_normalized.json --json
```

---

## 6. Start FastAPI backend (~20s)

```powershell
$env:PLATFORM_DATA_DIR = (Join-Path $env:TEMP "wrt-platform-demo")
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Health check (new terminal):

```powershell
curl -s http://127.0.0.1:8000/platform/health
```

---

## 7. Policy preview + blocked unsafe action (~40s)

```powershell
$H = @{ "X-Operator-Role" = "admin"; "X-Operator-Id" = "demo" }

# Ingest failure event
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/platform/failure-events/ingest -Headers $H -ContentType "application/json" -Body (@{
  event_id = "demo-ev-1"; endpoint_id = "demo-ep"; severity = "medium"; category = "dns"
  confidence = 0.9; summary = "demo"; recommended_action_key = "reset_dns"
} | ConvertTo-Json)

# Preview (dry-run metadata in response)
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/platform/remediation/preview -Headers $H -ContentType "application/json" -Body (@{
  endpoint_id = "demo-ep"; failure_event_id = "demo-ev-1"; requested_action = "reset_dns"
} | ConvertTo-Json)

# Blocked unsafe action (firewall reset — manual_only / high tier)
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/platform/failure-events/ingest -Headers $H -ContentType "application/json" -Body (@{
  event_id = "demo-fw-1"; endpoint_id = "demo-ep"; severity = "high"; category = "firewall"
  confidence = 0.99; summary = "demo"; recommended_action_key = "reset_firewall"
} | ConvertTo-Json)
$prv = Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/platform/remediation/preview -Headers $H -ContentType "application/json" -Body (@{
  endpoint_id = "demo-ep"; failure_event_id = "demo-fw-1"; requested_action = "reset_firewall"
} | ConvertTo-Json)
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/platform/remediation/execute -Headers $H -ContentType "application/json" -Body (@{
  preview_id = $prv.preview_id; confirmation_phrase = "RUN_FIREWALL_RESET"; dry_run = $false
} | ConvertTo-Json)
# Expect result=blocked
```

Execute with **default dry_run** (no `dry_run` field):

```powershell
# Uses preview_id from reset_dns preview above — result should be dry_run
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8000/platform/remediation/execute -Headers $H -ContentType "application/json" -Body (@{
  preview_id = "<preview_id>"; confirmation_phrase = "RUN_DNS_RESET"
} | ConvertTo-Json)
```

Audit tail:

```powershell
curl -s -H "X-Operator-Role: admin" http://127.0.0.1:8000/platform/audit/tail
```

---

## 8. Open dashboard (optional) (~30s)

```powershell
cd frontend
npm install
npm run dev
# Open http://localhost:3000 — points at backend when configured (see frontend/README if present)
```

---

## Demo data catalog

See [`demo_data/manifest.json`](../demo_data/manifest.json) for nine deterministic scenarios (healthy, proxy drift, DNS, TCP443, etc.).

---

## Related docs

- [production_readiness.md](production_readiness.md)
- [api_contract_platform.md](api_contract_platform.md)
- [interview_case_study_tier1.md](interview_case_study_tier1.md)
- [metrics.md](metrics.md)

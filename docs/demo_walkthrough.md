# Demo walkthrough — safe Endpoint Reliability Platform (local-first)

Scenario: **ICMP works but browser traffic fails** because of **WinHTTP/system proxy misconfiguration or browser-path issues**. This walkthrough stays **offline / non-destructive** until you explicitly run an allowlisted `.bat` (not required).

## Prerequisites

- Python **3.10+** recommended  
- Repo root as working directory  

```powershell
cd C:\path\to\Windows-Network-Recovery-Toolkit

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r failure_system\requirements.txt -r requirements-platform.txt
```

## 1) Start backend (`/platform/*` router)

Expose `PYTHONPATH` to the repo root so `platform_core` imports resolve.

```powershell
$env:PYTHONPATH = (Get-Location).Path
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Verify health (from a second terminal):

```powershell
Invoke-WebRequest http://127.0.0.1:8000/platform/health -UseBasicParsing | Select-Object -Expand Content
```

**RBAC lite (portfolio demo headers):**

| Scenario | Headers |
|---------|---------|
| Admin (full remediation + audit) | `X-Operator-Role: admin` |
| Viewer (metrics/incidents/events only) | `X-Operator-Role: viewer` |
| Operator | `X-Operator-Role: operator` (**preview + dry-run execute**) |
| Security / audits | `X-Operator-Role: security` (**alias** of **`security_auditor`**) |

`Invoke-WebRequest -Headers @{ "X-Operator-Role"="admin"; "X-Operator-Id"="walkthrough-demo" } http://127.0.0.1:8000/platform/audit`

Augmented KPIs (**`GET /platform/metrics`**) expose portfolio counters (**`proxy_changes_total`**, **`endpoint_heartbeat_total`**, etc.) aggregated from **`platform_signals.jsonl`** — see **`docs/metrics.md`**.

### Optional offline attribution staging

Append JSONL bundles with **`platform_core.storage.append_attribution_context`** (or tests) keyed by **`event_id`**, then call:

`Invoke-WebRequest -Headers @{...} http://127.0.0.1:8000/platform/attribution/<event-id>`

This exercises **`evidence/attribution_engine.py`** boundaries without invoking live collectors.

---

## 2) Run **`python -m platform_core.demo`** (fixture-only)

Uses temp `PLATFORM_DATA_DIR` — exercises policy + JSONL counters **without** calling Windows repair tooling.

```powershell
python -m platform_core.demo
```

---

## 3–6) Heartbeat → snapshot → failure event (+ optional FailureBlock link)

Minimal flow against the live API (**admin headers** assumed below):

### 3) Heartbeat (EndpointIdentity)

```powershell
$h = @{ "X-Operator-Role"="admin"; "X-Operator-Id"="walkthrough-demo" }
Invoke-WebRequest -Uri http://127.0.0.1:8000/platform/agent/heartbeat `
  -Method POST -Headers $h `
  -ContentType "application/json" `
  -Body '{"endpoint_id":"demo_ep_proxy_001","os_family":"Windows","os_version":"11","agent_version":"demo"}' `
  -UseBasicParsing
```

### 4) Sanitized snapshot

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8000/platform/snapshots `
  -Method POST -Headers $h `
  -ContentType "application/json" `
  -Body '{"endpoint_id":"demo_ep_proxy_001","proxy_state":{"curl_https_ok":false,"probe":"example.com"}}' `
  -UseBasicParsing
```

### 5) FailureEvent (ingestion)

Use a sanitized summary (no hostname / no private IPs).

```powershell
$body = @'
{
 "event_id": "demo-ev-proxy-1",
 "endpoint_id": "demo_ep_proxy_001",
 "failure_block_id": "",
 "severity": "medium",
 "category": "proxy",
 "confidence": 0.86,
 "summary": "HTTPS probe failures with WinHTTP indirect mode (sanitized narrative)",
 "recommended_action_key": "reset_proxy"
}
'@
Invoke-WebRequest http://127.0.0.1:8000/platform/failure-events/ingest -Method POST -Headers $h -ContentType application/json -Body $body -UseBasicParsing
```

### 6) Link to Failure Knowledge `FailureBlock` (when JSONL shards exist locally)

Populate `failure_block_id` on the FailureEvent UUID from `failure_system` diagnose shards, **or** call:

`GET /platform/failure-events/demo-ev-proxy-1`  

If the FailureBlock shard is absent, **`failure_block_linked.found`** is `false`.

---

## 7–10) Preview → firewall blocked → dry-run remediation

### 7) Remediation preview (proxy reset)

```powershell
$pv = @{ endpoint_id="demo_ep_proxy_001"; failure_event_id="demo-ev-proxy-1"; requested_action="reset_proxy"; surface="api" }
Invoke-WebRequest http://127.0.0.1:8000/platform/remediation/preview -Method POST -Headers $h -ContentType application/json -Body ($pv | ConvertTo-Json -Compress) -UseBasicParsing
```

Inspect JSON for **`confirmation_phrase`** (e.g. `RUN_PROXY_RESET`).

### 8) Firewall reset preview (shows policy disallow / high-tier block semantics)

Substitute **`demo-ev-fw`** or reuse snapshot with **`category`** `firewall` for narrative clarity; **`reset_firewall`** aliases to **`firewall_reset_manual_only`** (manual / high-tier only).

```powershell
$feFw = '{"event_id":"demo-ev-fw-1","endpoint_id":"demo_ep_proxy_001","severity":"high","category":"firewall","confidence":0.9,"summary":"fixture-firewall"}'
Invoke-WebRequest http://127.0.0.1:8000/platform/failure-events/ingest -Method POST -Headers $h -ContentType application/json -Body $feFw -UseBasicParsing
$pvFw = @{ endpoint_id="demo_ep_proxy_001"; failure_event_id="demo-ev-fw-1"; requested_action="reset_firewall"; surface="api" }
Invoke-WebRequest http://127.0.0.1:8000/platform/remediation/preview -Method POST -Headers $h -ContentType application/json -Body ($pvFw | ConvertTo-Json -Compress) -UseBasicParsing | Select-Object -Expand Content
```

Expect **`allowed_by_policy": false`** (high risk).

### 9) Attempt execute on firewall preview (blocked at policy/RBAC)

Paste `preview_id` from firewall preview JSON:

```powershell
$exe = @{ preview_id="<PASTE_PREVIEW_UUID>"; confirmation_phrase="RUN_FIREWALL_RESET"; dry_run=$false }
Invoke-WebRequest http://127.0.0.1:8000/platform/remediation/execute -Method POST -Headers $h -ContentType application/json -Body ($exe | ConvertTo-Json -Compress) -UseBasicParsing | Select-Object -Expand Content
```

Expect **`result":"blocked"`** — **no destructive automation**.

### 10) Allowed **`dry_run`** execute (typed confirmation matches proxy preview)

Operators may only **`dry_run`** (`X-Operator-Role: operator`); **admins** may request live **allowlisted** scripts on Windows with policy checks.

Use admin headers from step **7**:

```powershell
$exeDry = @{ preview_id="<proxy preview_id>"; confirmation_phrase="RUN_PROXY_RESET"; dry_run=$true }
Invoke-WebRequest http://127.0.0.1:8000/platform/remediation/execute -Method POST -Headers $h -ContentType application/json -Body ($exeDry | ConvertTo-Json -Compress) -UseBasicParsing | Select-Object -Expand Content
```

Expect **`result":"dry_run"`**.

---

## 11–13) Audit, metrics, frontend dashboard

### 11) Audit (`security_auditor` or **admin**)

```powershell
Invoke-WebRequest http://127.0.0.1:8000/platform/audit?limit=20 -Headers @{ "X-Operator-Role"="security_auditor"; "X-Operator-Id"="auditor-demo" } -UseBasicParsing | Select-Object -Expand Content
```

### 12) Metrics (incident clustering + KPIs)

```powershell
Invoke-WebRequest http://127.0.0.1:8000/platform/metrics -UseBasicParsing | Select-Object -Expand Content
```

Look for **`incident_cluster_count`**, **`repair_success_rate`**, **`dry_run_execution_count`**, etc.

### 13) Next.js `/platform`

```powershell
cd frontend
copy .env.local.example .env.local  # ensure NEXT_PUBLIC_PLATFORM_API=http://127.0.0.1:8000
npm install
npm run dev
```

Open **http://localhost:3000/platform** — banner + metrics + clustering counts + RBAC-role simulation (stored in **`localStorage`**, default **`admin`** for audit-rich UX).

---

## Optional: **`endpoint_agent`** (read-only loops)

```powershell
$env:ENDPOINT_AGENT_DRY_RUN="1"
python -m endpoint_agent --once
python -m endpoint_agent --once --api http://127.0.0.1:8000
```

---

Safety recap: preview-first, typed confirmation gates, **`dry_run`** default on demos, registry-backed allowlist, RBAC-lite headers, append-only **`platform_data/*.jsonl`**, **no outbound log shipping** in toolkit defaults.

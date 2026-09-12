# Startup observability (v0.3.0)

Operator guide for **endpoint startup-time proxy drift** collection on Windows. This complements platform metrics in [observability.md](observability.md) (API health, Prometheus) — it is **not** the same subsystem.

## What this solves

After logon, WinINET proxy settings may change while VPN clients, dev tools (Cursor, Node), or startup apps initialize. A stale `127.0.0.1:<port>` with no listener causes `ERR_PROXY_CONNECTION_FAILED` even when DNS and ping work.

Startup observability automates:

1. **Dead-proxy guardian** — clears **dead** localhost WinINET proxies only (no listener).
2. **Boot trace** — read-only sampling of WinINET, WinHTTP, listeners, and deltas for ~3 minutes after logon.

## Recommended operator flow

```powershell
$env:PYTHONPATH = (Get-Location).Path

# Every session — clear dead localhost + ensure guardian/boot-trace install
.\ensure-proxy.cmd
# LinkedIn ERR_PROXY_CONNECTION_FAILED with a flaky local Node proxy:
.\ensure-proxy.cmd prefer-direct

# Preview combined install (guardian + boot trace)
python -m src install-startup-observability --json

# Apply with typed confirmation
python -m src install-startup-observability --dry-run false --confirm INSTALL_STARTUP_OBSERVABILITY

# Collect read-only evidence bundle
python -m src collect-evidence-bundle

# Summarize boot trace JSONL
python -m src startup-observability-report --json

# Uninstall all artifacts
python -m src uninstall-startup-observability --dry-run false --confirm UNINSTALL_STARTUP_OBSERVABILITY
```

PowerShell wrappers: `scripts/install-startup-observability.ps1`, `scripts/collect-evidence-bundle.ps1`.

Operator runbook with recovery layers: [dead-proxy-guardian.md](dead-proxy-guardian.md).

## Architecture

```text
install-startup-observability
        ├── WNRT-DeadProxyGuardian (scheduled task or Startup hook)
        │         └── proxy-guardian --loop (dead + opt-in broken)
        └── WNRT-ProxyBootTrace (scheduled task or Startup hook, 30s delay)
                  └── proxy-boot-trace (read-only JSONL)
                            ↓
              collect-evidence-bundle / startup-observability-report
```

**Install order:** try per-user Scheduled Task first; on `Access is denied`, fall back to `%APPDATA%\...\Startup\WNRT-*.cmd` hooks automatically.

**Uninstall:** removes scheduled tasks and Startup hooks if present (idempotent).

## CLI reference (`python -m src`)

| Command | Role | Default | Live apply token |
|---------|------|---------|------------------|
| `install-startup-observability` | Guardian + boot trace bundle | preview | `INSTALL_STARTUP_OBSERVABILITY` |
| `uninstall-startup-observability` | Remove all artifacts | preview | `UNINSTALL_STARTUP_OBSERVABILITY` |
| `install-boot-trace-task` | Boot trace only | preview | `INSTALL_BOOT_TRACE_TASK` |
| `uninstall-boot-trace-task` | Boot trace only | preview | `UNINSTALL_BOOT_TRACE_TASK` |
| `install-guardian-task` | Guardian only | preview | `INSTALL_GUARDIAN_TASK` |
| `uninstall-guardian-task` | Guardian only | preview | `UNINSTALL_GUARDIAN_TASK` |
| `proxy-boot-trace` | One-shot trace loop | read-only | — |
| `startup-inventory` | Targeted startup inventory | read-only | — |
| `proxy-guardian` | Dead / broken / hold-direct guardian | dry-run | `CLEAR_DEAD_LOCALHOST_PROXY`; broken/hold: `--clear-broken` / `--hold-direct` + `PREFER_DIRECT_WININET` |
| `collect-evidence-bundle` | Package endpoint evidence | read-only | — |
| `startup-observability-report` | Summarize boot trace JSONL | read-only | — |
| `safe-search` | Timeout-capped file search | read-only | — |

Full flag reference: [cli_reference.md](cli_reference.md#startup-observability--proxy_drift-python--m-src).

## Audit artifacts

| Path | Content |
|------|---------|
| `logs/proxy_boot_trace.jsonl` | Post-logon WinINET/WinHTTP/listener samples + delta events |
| `logs/proxy_guardian.jsonl` | Guardian classification and action rows |
| `logs/startup_inventory.jsonl` | Startup inventory runs |
| `reports/evidence-bundle-*/` | Read-only bundle from `collect-evidence-bundle` |

## Schema versions

Structured JSON payloads use explicit `schema_version` fields:

| Schema | Module | Purpose |
|--------|--------|---------|
| `startup_observability.v1` | `startup_observability.py` | Combined install preview/result |
| `boot_trace_task.v1` | `boot_trace_task.py` | Boot trace task install/fallback |
| `guardian_task.v1` | `guardian_task.py` | Guardian task install/fallback |
| `startup_observability_report.v1` | `startup_observability_report.py` | Boot trace summary |
| `evidence_bundle.v1` | `evidence_bundle.py` | Bundle collector result |
| `safe_search.v1` | `safe_search.py` | Bounded file search result |

### `startup-observability-report` fields

| Field | Meaning |
|-------|---------|
| `samples` | Number of boot trace JSONL rows read |
| `first_observed_proxy_enable` / `first_observed_proxy_server` | First sample WinINET state |
| `final_proxy_enable` / `final_proxy_server` | Last sample WinINET state |
| `final_classification` | Last drift classification |
| `listener_found_final` | Whether a listener was present on final sample |
| `delta_events_seen` | Union of delta events (e.g. `proxy_enable_changed`, `listener_appeared`) |
| `recommended_next_step` | Operator guidance (observational) |
| `limitations` | Epistemic boundaries preserved |

### Evidence bundle contents (minimum)

- `proxy-health`, `proxy-status`, `proxy-path-status`, `proxy-owner`, `proxy-diagnose`
- `startup-inventory.json`, DNS lookups, WinINET/WinHTTP snapshots
- Short boot trace sample, recent JSONL tails

## `safe-search` targets and exclusions

Targets: `project`, `startup`, `logs`, `scripts` (no full user-profile recursion).

Always excluded directory names: `node_modules`, `.git`, `.cache`, `docker`.

Profile-scan exclusions (only when scanning under `%USERPROFILE%`): `temp`, `packages`, `edge`, `chrome`, plus known noisy AppData fragments.

Explicit scan roots are never skipped solely because an ancestor path contains `Temp`.

Caps: `--max-seconds` (default 20), `--max-files` (default 3000). Hitting a cap sets `timed_out: true`.

## Safety boundaries

| Allowed | Blocked without confirmation |
|---------|-------------------------------|
| Read registry, netstat, startup inventory | Registry mutation (except guardian dead-proxy clear with token) |
| Boot trace sampling | Process kill, firewall reset |
| Evidence bundle collection | Disabling active localhost dev proxies |

Guardian only remediates when classification is **dead** localhost proxy (enabled, no listener). Active dev proxies with listeners are preserved.

Observation ≠ proof of registry writer identity. Listener correlation is not malware attribution.

## Verification

```powershell
schtasks /Query /TN WNRT-DeadProxyGuardian
schtasks /Query /TN WNRT-ProxyBootTrace
dir "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WNRT-*.cmd"
```

## Module map

| File | Role |
|------|------|
| `src/proxy_drift/startup_observability.py` | Combined install/uninstall orchestration |
| `src/proxy_drift/boot_trace_task.py` | Boot trace scheduled task + Startup fallback |
| `src/proxy_drift/guardian_task.py` | Guardian scheduled task + Startup fallback |
| `src/proxy_drift/startup_hook.py` | Shared Startup `.cmd` helpers |
| `src/proxy_drift/boot_trace.py` | Trace loop and delta detection |
| `src/proxy_drift/guardian.py` | Dead-proxy guardian logic |
| `src/proxy_drift/evidence_bundle.py` | Read-only bundle collector |
| `src/proxy_drift/startup_observability_report.py` | JSONL summarizer |
| `src/proxy_drift/safe_search.py` | Bounded file search |
| `src/proxy_drift/handlers.py` | CLI handlers wired from `src/cli.py` |

Tests: `tests/test_proxy_drift_toolkit.py`.

## Dual CLI note

- **`python -m windows_network_toolkit`** — primary portfolio CLI (`proxy-status`, `proxy-health`, analytics, governance).
- **`python -m src`** — extended Windows operator CLI including **all startup observability commands above**.

Do not duplicate startup observability into `windows_network_toolkit` unless explicitly requested; docs standardize on `python -m src` for this workflow.

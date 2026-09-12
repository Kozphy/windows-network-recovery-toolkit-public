# Runbook: Active Proxy Reverter (ACTIVE_REVERTER)

## Symptoms

- `proxy-investigate` reports repeated `ProxyEnable` toggles
- `proxy-disable` does not stick within minutes
- Listener on `127.0.0.1:<port>` owned by `node.exe` or similar

## Platform state path (expected)

```
NORMAL → LOCAL_PROXY_ENABLED → (optional PROXY_FAILURE) → ROOT_CAUSE_IDENTIFIED (with Sysmon proof)
```

## Triage (observation tier)

1. Run investigation:
   ```powershell
   python -m src proxy-investigate --since 30m
   ```
2. Note **attribution level** — `CORRELATED` is not `PROVEN_REGISTRY_WRITER`.
3. Check v2 decision preview (no host mutation):
   ```powershell
   curl -X POST http://127.0.0.1:8000/platform/v2/decisions/run `
     -H "Content-Type: application/json" `
     -H "X-Operator-Role: operator" `
     -d '{"observations":[{"signal_name":"wininet_proxy_enabled","value":1},{"signal_name":"localhost_proxy_detected"}]}'
   ```

## Recovery (requires elevation)

Policy engine returns **PREVIEW** until proof + confirmation. Live recovery needs Administrator:

```powershell
# Run as Administrator
.\scripts\run_proxy_recovery_admin.ps1
```

## Verification

1. Confirm proxy disabled: `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable`
2. Confirm no listener on prior port: `netstat -ano | findstr LISTENING`
3. Re-run `proxy-investigate --since 10m` — transitions should stop

## Escalation

| Condition | Action |
|-----------|--------|
| Unknown binary path | Collect Sysmon Event ID 13; do not auto-kill |
| Security product proxy | Add to `config/proxy_allowlist.yaml`; document vendor |
| Repeated re-enable after admin script | Capture process tree; open security incident |

## MTTR metrics

Track in Grafana: `platform_reliability_mttr_seconds`, `proxy_change_total`, `platform_policy_preview_total`.

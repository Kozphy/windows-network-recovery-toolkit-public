# Demo fixtures (synthetic)

Canonical Tier-1 demo JSON lives under [`tests/fixtures/demo/`](../../tests/fixtures/demo/).

| Fixture | Scenario |
|---------|----------|
| `healthy_endpoint.json` | Baseline — no drift |
| `proxy_drift_correlated_only.json` | Listener correlation without writer proof |
| `sysmon_registry_writer_proven.json` | Sysmon-class writer telemetry |
| `final_causation_browser_path_failure.json` | Writer + network impact |
| `suspicious_external_proxy.json` | External proxy host |
| `stale_localhost_proxy_listener.json` | Stale localhost listener |
| `developer_tool_proxy_allowed.json` | Allowlisted dev tooling |

Run without admin or host mutation:

```bash
python -m src demo-scenario healthy --format both
make demo-proxy-drift
```

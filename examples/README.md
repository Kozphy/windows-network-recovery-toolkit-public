# Examples

This folder holds **safe, fictional** samples for documentation and portfolio review. **Do not** treat these as production telemetry.

---

## Files

| File | Purpose |
|------|---------|
| `sample_failure_block.json` | Synthetic FailureBlock-shaped record — no real hostnames, IPs, or corporate domains |
| `proxy_reasoning_audit_record.json` | Fictional `proxy_reasoning_run` row (signals, policy, limitations) |
| `proof_engine_localhost_proxy_confirmed_example.json` | Fictional proof contrast (demo port `127.0.0.1:54321`) |
| `synthetic_platform_audit.jsonl` | Fictional append-only audit tail (`demo-user`, `demo-ev-001`) |
| `evidence/` | Portfolio classification fixtures — see [evidence/README.md](evidence/README.md) |

---

## Safety boundaries

- Do **not** add real `logs/`, `reports/`, or JSONL exports from production machines.
- Use `tests/fixtures/` for automated test inputs (deterministic CI).
- Copy `config/last_known_good_proxy.example.json` → `config/last_known_good_proxy.json` locally for known-good templates (latter is gitignored).

---

## Usage with CLI

```powershell
python -m windows_network_toolkit proxy-status --fixture examples/evidence/DEAD_PROXY_CONFIG.json
python -m windows_network_toolkit diagnose --proof --fixture examples/evidence/DEAD_PROXY_CONFIG.json
```

---

## Audit notes

Fixture JSON is static — timestamps may be fictional. For hash-chain verification demos, use `tests/fixtures/analytics/audit_sample/` and `python -m windows_network_toolkit audit verify <path>`.

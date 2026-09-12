# Portfolio evidence fixtures

Realistic JSON evidence bundles for interview demos and tests.

| File | Primary classification |
|------|------------------------|
| `DEAD_PROXY_CONFIG.json` | Dead localhost WinINET proxy |
| `WININET_WINHTTP_MISMATCH.json` | Stack divergence |
| `LOCAL_PROXY_ACTIVE.json` | Active dev-style listener |
| `REVERTER_SUSPECTED.json` | Proxy re-enable after disable |
| `POSSIBLE_MITM_RISK.json` | TLS triage (not confirmed MITM) |

Used by `tests/test_portfolio_evidence_suite.py` and [docs/demo-script.md](../docs/demo-script.md).

```powershell
python -m windows_network_toolkit proxy-status --fixture examples/evidence/DEAD_PROXY_CONFIG.json
```

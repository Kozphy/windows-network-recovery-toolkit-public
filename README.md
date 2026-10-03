# Windows Network Recovery Toolkit (public mirror)

**Public edition** of the Technology Risk & Control Analytics toolkit for Windows endpoint evidence: proxy drift, TLS-path comparison, IPv6/DNS-edge diagnosis, policy-gated remediation **previews**, and a **read-only fixture-mode** demo API + frontend.

> This repository is a **sanitized mirror** of a private monorepo. Enterprise SaaS, Stripe billing, fleet multi-tenant, and OpenClaw automation stay private. See [docs/private-public-split.md](docs/private-public-split.md).

**Not:** antivirus, EDR, XDR, malware attribution, or autonomous security software.

## Quick start (CLI)

```powershell
pip install -e ".[dev]"
$env:PYTHONPATH = (Get-Location).Path

python -m windows_network_toolkit proxy-status --fixture examples/evidence/DEAD_PROXY_CONFIG.json
python -m windows_network_toolkit ipv6-path --dry-run true
python -m windows_network_toolkit dns-edge-status
python -m windows_network_toolkit dns-edge-fix --dry-run true
```

Remediation defaults to **dry-run**. Live apply requires elevation and an exact confirmation token (`DISABLE_WININET_PROXY`, `PREFER_IPV4_OVER_IPV6`, `RESTORE_IPV6_PREFERENCE`, `FIX_ERR_NAME_NOT_RESOLVED`).

`agent once` is not available in this edition: it depends on the private endpoint-agent package.

## Demo API + frontend (fixture / read-only)

```powershell
# API (loopback, fixture mode)
$env:PLATFORM_FIXTURE_MODE = "1"
python -m uvicorn backend.public_app:app --host 127.0.0.1 --port 8000

# Frontend
cd frontend
copy .env.local.example .env.local
npm install
npm run dev
```

Open http://localhost:3000 and Swagger at http://127.0.0.1:8000/docs.

Public demo mounts health / platform / trisk fixture routes only. It does **not** enable Stripe billing or silent host mutation.

## Safety

- Observation ≠ proof · correlation ≠ causation · classification ≠ accusation
- Dry-run by default; blocked actions remain blocked (`ADAPTER_DISABLE`, process kill, firewall reset)
- Run `python tools/public_release_audit.py --tracked-only` before publishing

## Docs

- [docs/ONBOARDING.md](docs/ONBOARDING.md)
- [docs/safety_model.md](docs/safety_model.md)
- [docs/runbooks/ipv6-path-blackhole.md](docs/runbooks/ipv6-path-blackhole.md)
- [docs/runbooks/dns-edge-err-name-not-resolved.md](docs/runbooks/dns-edge-err-name-not-resolved.md)
- [docs/private-public-split.md](docs/private-public-split.md)
- [PUBLIC_RELEASE_CHECKLIST.md](PUBLIC_RELEASE_CHECKLIST.md)

## License

AGPL-3.0-only — see [LICENSE](LICENSE).

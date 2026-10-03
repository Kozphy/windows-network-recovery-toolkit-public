# Why is it broken? — unified browser/path investigate

Edge hangs, `ERR_NAME_NOT_RESOLVED`, or “coding works but browser doesn’t.” Run one read-only command that ranks **proxy vs DNS/Edge vs IPv6** hypotheses and prints `operator_next_step`.

**Not:** malware/attack attribution, ISP repair, or automatic remediation.

## One-shot

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m windows_network_toolkit why-broken

# Optional: probe the exact hanging page
python -m windows_network_toolkit why-broken --url "https://example.com/page"
```

## How to read the JSON

| Field | Meaning |
|-------|---------|
| `primary_hypothesis` | Highest-scoring correlation (not proof) |
| `hypotheses[]` | Ranked signals with `score` / `summary` / `next_command` |
| `coding_vs_browser` | Why Cursor/dev tools can work while Edge stalls |
| `attack_attribution.claimed` | Always `false` here — use proof/writer tools separately |
| `operator_next_step` | Exact next dry-run/diagnose command when applicable |

## Typical primaries

| Id / classification | Pattern |
|---------------------|---------|
| `proxy` / dead or localhost proxy | WinINET points at broken/local proxy |
| `dns_edge` / DNS fail or ERR_NAME likely | OS DNS or Edge resolver posture |
| `ipv6_path` / `IPV6_PATH_BLACKHOLE` | IPv4 OK, IPv6 fail (dual-stack hang risk) |
| `client_or_site` | Host path looks OK — next: `edge-triage [--inprivate works\|fails]` |

**Mitigated IPv6:** if prefer-IPv4 is already set **and** the host has no global IPv6 (or the Wi-Fi IPv6 binding is off), the blackhole is inert. `ipv6_path` then scores 0.2 with `ipv6_mitigated: true`, so it no longer outranks client-side causes, and `next_command` points to `edge-triage` instead of "reboot".

## Related commands

- `edge-triage` — Edge won't load / slow / blank: one question + token fix ladder ([edge-loading-triage.md](edge-loading-triage.md))
- `proxy-status`, `proxy-disable --dry-run true`
- `dns-edge-status`, `dns-edge-fix --dry-run true`
- `ipv6-path`, `ipv6-prefer-ipv4 --dry-run true`
- `browser-blank-screen`, `browser-blank-screen-fix --dry-run true` (blank/black UI, e.g. LinkedIn)

## Limitations

- Ranked hypothesis is correlation across probes.
- Does not prove a single root cause or an attack.
- See `windows_network_toolkit/why_broken.py`.
- Blank LinkedIn/Edge UI after path looks OK: [browser-blank-screen.md](browser-blank-screen.md).

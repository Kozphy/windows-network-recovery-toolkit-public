# Edge blank / black screen (LinkedIn / Upwork-style)

When HTTPS origin returns **200** (or a Cloudflare challenge) but Edge shows a **blank or black UI** (common on [LinkedIn](https://www.linkedin.com/) and [Upwork](https://www.upwork.com/)), treat it as a **client render/cache** problem after ruling out proxy/DNS/IPv6.

**Not:** malware attribution, LinkedIn/Upwork outage proof, or automatic extension wipe.

## One-shot diagnose (+ optional fix preview)

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m windows_network_toolkit browser-blank-screen
python -m windows_network_toolkit browser-blank-screen --url "https://www.linkedin.com/"
python -m windows_network_toolkit browser-blank-screen --url "https://www.upwork.com/"
# Preferred for agents/operators: diagnose + dry-run preview in one payload
python -m windows_network_toolkit browser-blank-screen --with-fix-preview --url "https://www.linkedin.com/"
```

Also reachable from unified investigate when prefer-IPv4 is already on:

```powershell
python -m windows_network_toolkit why-broken --url "https://www.linkedin.com/"
python -m windows_network_toolkit why-broken --url "https://www.upwork.com/"
```

| Classification | Pattern |
|----------------|---------|
| `BROWSER_BLANK_SCREEN_CACHE_GPU` | Origin IPv4 OK; Edge GPU/cache likely |
| `IPV6_BLACKHOLE_LIKELY` | Dual-stack blackhole without prefer-IPv4 — fix path first |
| `IPV6_MITIGATED_TRY_BLANK_SCREEN_FIX` | Prefer-IPv4 on; blank UI persists |
| `ORIGIN_UNREACHABLE` | Origin probe failed — use why-broken / dns-edge |

## Remediation (preview default)

Stops Edge (unless `--no-stop-edge`), clears GPU/Code/Service Worker caches, and disables hardware acceleration in Edge Preferences.

`--with-fix-preview` on diagnose never applies; it only attaches a dry-run plan and the exact apply command/token.

```powershell
python -m windows_network_toolkit browser-blank-screen --with-fix-preview
python -m windows_network_toolkit browser-blank-screen-fix --dry-run true

# Live apply (closes Edge) — typed token required
python -m windows_network_toolkit browser-blank-screen-fix `
  --dry-run false `
  --confirm CLEAR_EDGE_BLANK_SCREEN_CACHES
```

Then reopen Edge **InPrivate** and retest LinkedIn or Upwork. Audit: `.audit/browser-blank-screen.jsonl`.

**Agent note:** On “Edge blank screen” reports, run `--with-fix-preview` immediately; ask only for `CLEAR_EDGE_BLANK_SCREEN_CACHES` (or apply in the same turn if the user already typed it).

## Related

- `edge-triage` — if the cache clear was already applied (audit log, last 72 h) and the page still fails, triage recommends extensions/site repair or escalation instead of clearing caches again ([edge-loading-triage.md](edge-loading-triage.md))
- `ipv6-path` / Wi-Fi IPv6 binding — dual-stack hangs while loading
- `dns-edge-status` — `ERR_NAME_NOT_RESOLVED`
- `browser-profile repair-preview` — site-scoped cookie/SW cleanup
- `browser-profile repair-apply <preview-id> --confirm BROWSER_SITE_REPAIR_APPLY` — gated apply

## Limitations

- Origin 200 + blank UI is correlation, not a single root cause.
- Cleanup does not repair ISP IPv6; keep prefer-IPv4 / Wi-Fi binding mitigation as needed.
- Extensions or MDM can still blank the page after apply.

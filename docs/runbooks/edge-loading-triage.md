# Edge won't load / slow / spinning — one-shot triage

Use this runbook for generic "Edge won't load" reports where the exact cause is unclear. One read-only command runs the network checks, reads Edge client state, and checks the audit log for recent fixes. It returns an ordered fix ladder in which every rung carries its exact confirmation token, plus **one** question for the operator. The operator's reply is a token, so the agent can apply the fix without another round-trip.

**Not:** automatic remediation, a site-outage verdict, or malware attribution. Triage never applies anything.

## One-shot

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m windows_network_toolkit edge-triage

# Optional evidence that sharpens the ladder
python -m windows_network_toolkit edge-triage --url "https://example.com/page"
python -m windows_network_toolkit edge-triage --inprivate works   # loads in InPrivate
python -m windows_network_toolkit edge-triage --inprivate fails   # also fails in InPrivate
```

`--inprivate` is operator-reported evidence (default `unknown`). `--url` enables URL probes and the site-scoped repair rung. `--sample-seconds` (default 3) sets the CPU sampling window.

## Automatic runtime detection (edge_client route)

Triage also samples every `msedge.exe` process twice, a few seconds apart, without asking first (`windows_network_toolkit/edge_runtime.py`, read-only). Results land in `detected_issues[]`, ordered by severity:

| `id` | Severity | Detected when | Manual step (toolkit never ends processes) |
|------|----------|---------------|---------------------------------------------|
| `tab_frozen` | high | A tab renderer uses ≥ 80% of a core over the sample | Exit page, or Shift+Esc → End process, then reload once |
| `extension_busy` | medium | An extension process uses ≥ 80% of a core | Shift+Esc to identify it; disable it |
| `restart_pending` | medium | Edge started before the last live cache clear / extension-policy change in `.audit/` | Close Edge completely and reopen |
| `memory_pressure` | medium | Free RAM < max(2 GB, 10% of total) | Close tabs/apps, restart Edge |
| `gpu_acceleration_off` | medium | A capable GPU is present **and** the GPU/browser process has `--disable-gpu`-style flags or `Local State` disables acceleration | Turn on "Use graphics acceleration when available" |

When the top issue is `high` or `restart_pending`, `ask_user` starts with that manual step. `diagnosis` is a single plain line: the top issue's summary, or the classification meaning when nothing is detected.

The hardware-acceleration setting comes from `User Data\Local State` → `hardware_acceleration_mode.enabled`. If the key is absent, Chromium's default (enabled) applies. The legacy profile `Preferences` key is used only when `Local State` is unreadable (`edge.hardware_acceleration_source`).

Installed risky extensions that the HKCU `ExtensionSettings` policy already blocks are marked `blocked_by_policy: true`. They no longer produce the extension-block rung.

## Routes

| `route` | `classification` | Meaning / recommended token |
|---------|------------------|-----------------------------|
| `network` | `NETWORK_PATH_LIKELY` | why-broken primary ≥ 0.7: dead proxy → `DISABLE_WININET_PROXY`, DNS/Edge → `FIX_ERR_NAME_NOT_RESOLVED`, IPv6 blackhole without prefer-IPv4 → `PREFER_IPV4_OVER_IPV6` |
| `unreachable` | `SITE_UNREACHABLE` | URL fails on IPv4 and IPv6 — no client fix offered |
| `edge_client` | `EDGE_PROFILE_STATE_LIKELY` | InPrivate works → block installed risky extensions (`DISABLE_EDGE_EXTENSIONS_VIA_POLICY`) or site repair (`BROWSER_SITE_REPAIR_APPLY`) |
| `edge_client` | `EDGE_CACHE_GPU_LIKELY` | InPrivate fails → clear caches (`CLEAR_EDGE_BLANK_SCREEN_CACHES`) |
| `edge_client` | `EDGE_CLIENT_STATE_LIKELY` | InPrivate untested → cache rung first, or profile rungs first if caches were cleared recently |
| `edge_client` | `EDGE_STATE_EXHAUSTED_ESCALATE` | Caches cleared in the last 72 h **and** InPrivate fails → no token offered; escalate |
| `edge_client` | `SITE_DATA_FIXED_BEFORE` | `.audit/browser-diff.jsonl` has a live site repair for this domain (or its parent/subdomain) and InPrivate is not `fails` → `BROWSER_SITE_REPAIR_APPLY` first |

## One reply, no question (`ask_kind`)

`ask_kind` is `token` when the InPrivate answer cannot change the recommendation. In that case `ask_user` is a bare offer: `Reply <TOKEN> to apply: <changes>`. This happens in two cases:

- The site was repaired before (`previous_site_repair` is set, classification `SITE_DATA_FIXED_BEFORE`).
- InPrivate is untested and every other rung is spent: caches cleared in the last 72 h, and risky extensions blocked by policy or not installed. The one rung left is the recommendation.

If that rung closes Edge (cache clear, site repair) and a frozen tab or pending restart was detected, the offer notes that closing Edge also clears it. There is no separate "end the tab first" step. Otherwise `ask_kind` is `question` and the InPrivate question is asked.

## Key fields

| Field | Meaning |
|-------|---------|
| `fix_options[]` | Ordered rungs: `id`, `token`, `preview_command`, `apply_command`, `changes`, `undo`, `when` |
| `recommended_fix` | First rung for this evidence (or `null` on escalate/unreachable) |
| `ask_user` | The single question (or bare token offer); each answer maps to a token |
| `ask_kind` | `token` (relay as a one-line offer) or `question` |
| `previous_site_repair` | Last live `repair-apply` matching this domain (`domain`, `timestamp_utc`, `preview_id`) |
| `operator_next_step` | Exact apply command and the required token |
| `diagnosis` | One plain-language line: where the issue most likely is |
| `detected_issues[]` | Runtime findings: `id`, `severity`, `summary`, `evidence`, `user_action` |
| `manual_steps[]` | The `user_action` of every detected issue, in order |
| `runtime` | Sample summary: process count, Edge memory, free RAM, uptime, GPU adapters |
| `risky_extensions[]` | `cloudflare-risk` preset with `installed` true/false/null and `blocked_by_policy` |
| `recent_blank_screen_fix` | Last live cache clear in `.audit/browser-blank-screen.jsonl` (`age_hours`, `recent`) |

## Agent flow (one pause)

1. User reports "Edge won't load / slow / spinning": run `edge-triage` immediately (add `--url` and `--inprivate` if the user said so).
2. Relay `ask_user` verbatim, plus the `changes` / `undo` of the rungs it mentions.
3. User replies with a token: run that rung's `preview_command`, then its `apply_command` in the same turn. If the message already contained the token, do this in the first turn.
4. Never apply without the exact token string from the user.

## Limitations

- Ranking is correlation across probes and operator-reported evidence, not proof of root cause.
- Extension `installed` checks scan the Default Edge profile only.
- The recent-fix window reads the local audit log; a cleared/rotated log hides prior fixes.
- The CPU sample covers a few seconds. A busy tab correlates with "This page isn't responding" but does not name the site.
- A past site repair shows the fix was applied, not that it worked. A recurring symptom is what makes it the first rung.
- Tests route audit writes to a temp dir (`tests/windows_network_toolkit/conftest.py`), so test runs cannot fake "recently applied" fixes in the real `.audit` logs.
- Known gap: the blank-screen fix's hardware-acceleration writer still edits the legacy `Preferences` key, which Edge ignores.
- See `windows_network_toolkit/edge_triage.py`.

# Edge extension policy (gated)

Temporarily **block** specific Edge extensions via HKCU `ExtensionSettings` policy — without uninstalling them and without touching other extensions.

**Not** a Cloudflare bypass. Useful when InPrivate works and AdGuard / User-Agent Switcher are suspected.

## Tokens

| Action | Exact confirm token |
|--------|---------------------|
| Block listed IDs | `DISABLE_EDGE_EXTENSIONS_VIA_POLICY` |
| Remove policy value | `RESTORE_EDGE_EXTENSIONS_POLICY` |

## Preview (default)

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m windows_network_toolkit edge-extensions-disable --preset cloudflare-risk --dry-run true
```

Preset `cloudflare-risk` targets only:

- AdGuard AdBlocker (`bgnkhhnnamicmpeenaelnjfhikgbkllg`)
- User-Agent Switcher (`djflhoibgkdhkhhcedjiklpkjnoahfmg`)

Each entry in the preview's `targets[]` carries `installed`: `true`/`false` from the Default profile's `Extensions` folder, or `null` when that folder can't be read. The written policy is the same either way (blocking an absent ID is harmless). `edge-triage` only offers this rung when at least one target is installed.

Or pass explicit IDs:

```powershell
python -m windows_network_toolkit edge-extensions-disable --ids bgnkhhnnamicmpeenaelnjfhikgbkllg,djflhoibgkdhkhhcedjiklpkjnoahfmg --dry-run true
```

## Live apply

```powershell
python -m windows_network_toolkit edge-extensions-disable `
  --preset cloudflare-risk `
  --dry-run false `
  --confirm DISABLE_EDGE_EXTENSIONS_VIA_POLICY `
  --elevate
```

`--elevate` shows a UAC prompt when `HKCU\SOFTWARE\Policies\Microsoft\Edge` is admin-ACL locked (common on managed PCs).

## Restore (unblock)

```powershell
python -m windows_network_toolkit edge-extensions-restore --dry-run true
python -m windows_network_toolkit edge-extensions-restore `
  --dry-run false `
  --confirm RESTORE_EDGE_EXTENSIONS_POLICY `
  --elevate
```

## Same-message agent rule

If the operator’s **first** message both asks to fix and includes the exact token, agents must diagnose/preview **and** live-apply in **one turn** (still no silent apply without the token).

Example:

> Fix Cambridge Cloudflare loop — `DISABLE_EDGE_EXTENSIONS_VIA_POLICY`

## Limitations

- Policy **blocks** runtime; it does not delete extension files.
- Does not edit HMAC-protected `Secure Preferences`.
- The `installed` flag scans the Default Edge profile only; other profiles are not inspected.
- Audit: `.audit/edge-extensions-policy.jsonl`.

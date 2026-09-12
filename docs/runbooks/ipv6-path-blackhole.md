# IPv6 path blackhole — operator runbook

Edge or Chromium tabs keep loading while WinINET proxy is healthy and IPv4 HTTPS works. Dual-stack destinations still advertise AAAA; Happy Eyeballs waits on a blackholed IPv6 path.

**Not:** ISP IPv6 repair, malware attribution, or automatic adapter disable.

## One-shot investigate (preferred)

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m windows_network_toolkit ipv6-path
```

Returns proxy/DNS/Wi-Fi context, multi-host IPv4/IPv6 probes, and `operator_next_step` with the exact next command.

## Read-only path status

```powershell
python -m windows_network_toolkit ipv6-path-status
```

| Classification | Pattern |
|----------------|---------|
| `IPV6_PATH_BLACKHOLE` | IPv4 HTTPS OK (any fallback host), IPv6 probe fail |
| `IPV6_PATH_OK` | Both probes OK — look elsewhere for Edge hangs |
| `NETWORK_PATH_DEGRADED` | Both fail across fallbacks — check Wi-Fi / DNS / proxy first |

## Prefer-IPv4 remediation (preview default)

Host mitigation: `DisabledComponents |= 0x20`.

```powershell
python -m windows_network_toolkit ipv6-prefer-ipv4 --dry-run true

# Elevated live apply
python -m windows_network_toolkit ipv6-prefer-ipv4 --dry-run false --confirm PREFER_IPV4_OVER_IPV6
```

Dry-run JSON includes `operator_next_step` (`kind` / `command` / `reason`) after the preview so the next action is explicit (apply elevated + reboot).

Then **reboot**. Audit: `.audit/ipv6-prefer-ipv4.jsonl`.

## Restore IPv6 preference (after ISP/router IPv6 is healthy)

Clears only the prefer-IPv4 bit (`DisabledComponents &= ~0x20`); other bits preserved.

```powershell
python -m windows_network_toolkit ipv6-restore-preference --dry-run true

# Elevated live apply
python -m windows_network_toolkit ipv6-restore-preference --dry-run false --confirm RESTORE_IPV6_PREFERENCE
```

Dry-run attaches path `diagnosis` (when available) and `operator_next_step`. If classification is still `IPV6_PATH_BLACKHOLE`, next step is **`keep_prefer_ipv4`** — do **not** live-apply restore.

Audit: `.audit/ipv6-restore-preference.jsonl`.

## Safety boundaries

- Dry-run is default for prefer and restore.
- Tokens: `PREFER_IPV4_OVER_IPV6`, `RESTORE_IPV6_PREFERENCE`.
- `ADAPTER_DISABLE` stays blocked.
- Optional manual escalation (operator-owned):

```powershell
Disable-NetAdapterBinding -Name "Wi-Fi" -ComponentID ms_tcpip6
```

## Limitations

- IPv4-ok + IPv6-fail correlates with Edge hang; it does not prove a single root cause.
- Prefer-IPv4 is a host mitigation, not an ISP/router IPv6 fix.
- Windows does not auto-clear prefer-IPv4 when IPv6 recovers — use `ipv6-restore-preference`.
- See `windows_network_toolkit/ipv6_path.py` and `windows_network_toolkit/safety.py`.

# DNS / Edge ERR_NAME_NOT_RESOLVED — operator runbook

Browser shows `ERR_NAME_NOT_RESOLVED` (or related name failures) while Cursor or other non-browser clients may still work. Common pattern: router-first DNS ordering and/or Edge Secure DNS / built-in async DNS diverging from OS resolver.

**Not:** ISP WAN repair, malware attribution, corporate NRPT override, or automatic firewall/adapter changes.

Related: [ipv6-path-blackhole.md](ipv6-path-blackhole.md) when tabs **hang** (dual-stack) rather than fail DNS.

## Read-only diagnosis

```powershell
$env:PYTHONPATH = (Get-Location).Path
python -m windows_network_toolkit dns-edge-status
```

| Classification | Pattern |
|----------------|---------|
| `DNS_RESOLVE_FAILED` | OS Resolve-DnsName fails all probe hosts |
| `ERR_NAME_NOT_RESOLVED_LIKELY` | OS DNS OK, but primary DNS not public-first and/or Edge not forced to OS DNS |
| `DNS_EDGE_OK` | Probes OK, public DNS preferred, Edge DoH off + built-in DNS disabled |

JSON includes `wifi`, `edge_policy`, `resolves`, `planned_dns_servers`, and `operator_next_step`.

## Preview / apply fix (dry-run default)

Sets Wi-Fi DNS to `1.1.1.1`, `8.8.8.8`, then gateway; writes HKCU Edge policy `DnsOverHttpsMode=off` and `BuiltInDnsClientEnabled=0`; flushes DNS. Optional `--restart-edge` stops `msedge.exe`.

```powershell
python -m windows_network_toolkit dns-edge-fix --dry-run true

# Elevated live apply
python -m windows_network_toolkit dns-edge-fix --dry-run false --confirm FIX_ERR_NAME_NOT_RESOLVED --restart-edge
```

Audit: `.audit/dns-edge-fix.jsonl`.

## Safety boundaries

- Dry-run is default.
- Token: `FIX_ERR_NAME_NOT_RESOLVED` (exact match).
- Does not reset firewall, disable adapters, or kill proxy processes.
- Edge restart only when `--restart-edge` is passed on live apply.

## Rollback (operator-owned)

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Edge" -Name BuiltInDnsClientEnabled -ErrorAction SilentlyContinue
ipconfig /flushdns
```

## Limitations

- OS DNS OK does not prove Edge's resolver path is healthy.
- MDM / NRPT may override adapter DNS and Edge policy.
- Prefer public DNS is a host mitigation, not proof of router/ISP DNS malice.
- See `windows_network_toolkit/dns_edge.py` and `windows_network_toolkit/safety.py`.

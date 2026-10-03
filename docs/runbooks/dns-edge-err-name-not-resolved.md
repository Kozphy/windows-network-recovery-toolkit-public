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

## Is it the site or this PC? (`--url`)

When one specific site fails (`ERR_NAME_NOT_RESOLVED`, `DNS_PROBE_FINISHED_NXDOMAIN`), pass it:

```powershell
python -m windows_network_toolkit dns-edge-status --url https://example.net/
```

This asks the domain's **own nameservers directly** (read-only, `windows_network_toolkit/dns_authoritative.py`). It walks the referrals from the root servers to the TLD to the domain's delegated nameservers. Then it queries each of those nameservers with recursion off, and compares with `1.1.1.1` / `8.8.8.8` and this PC's resolver. Results land in `authoritative_check`, `target_url`, and `target_verdict`.

| `authoritative_check.classification` | Meaning | `target_verdict` |
|---|---|---|
| `NOT_DELEGATED_NXDOMAIN` | TLD registry says the domain doesn't exist (unregistered / expired / suspended) | `site_side` |
| `LAME_DELEGATION` | Delegated nameservers all refuse or fail (e.g. Route 53 hosted zone deleted) | `site_side` |
| `AUTHORITATIVE_UNREACHABLE` | No delegated nameserver replies | `site_side` |
| `NAME_NOT_IN_ZONE` | Zone answers but has no record for this hostname | `site_side` |
| `AUTHORITATIVE_OK_RESOLVERS_FAIL` | Nameservers answer, public resolvers fail (often broken DNSSEC; not checked) | `site_side` |
| `PARTIAL_LAME_DELEGATION` | Some nameservers fail, so lookups fail intermittently | `site_side_intermittent` |
| `AUTHORITATIVE_OK_CLIENT_RESOLVER_FAILS` | Site and public DNS fine, this PC's resolver fails | `client_side` |
| `AUTHORITATIVE_OK` | Resolves everywhere | `dns_ok` |
| `INCONCLUSIVE_DIRECT_DNS_BLOCKED` / `INCONCLUSIVE` / `NOT_A_HOSTNAME` | Network blocks direct UDP/53, walk failed, or target is an IP | `inconclusive` |

A `site_side*` verdict sets `operator_next_step.kind = site_side_dns` with no command: changing local DNS or Edge cannot fix it, so `FIX_ERR_NAME_NOT_RESOLVED` is **not** offered. Tell the user the site owner must fix their DNS hosting (recreate the zone or correct the registrar's NS records). A `client_side` verdict points to the gated `dns-edge-fix` below.

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
- `--url` check: one UDP/IPv4 A query per server from one vantage point at one moment; DNSSEC is not validated, and networks that allow DNS only to the local resolver make it inconclusive.
- See `windows_network_toolkit/dns_edge.py` and `windows_network_toolkit/safety.py`.

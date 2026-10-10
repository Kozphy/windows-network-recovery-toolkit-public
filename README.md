# Windows Network Recovery Toolkit

**Find out why a Windows PC can't get online when the network looks "connected", then fix it safely.**

WNRT is a Python command-line toolkit (`wnrt`) for the Windows connectivity problems that "reset everything" fixes tend to hide: a leftover proxy, a DNS failure that only shows up in the browser, or an IPv6 path that silently drops traffic. It shows you the cause first, and every fix is a preview until you explicitly apply it.

<!-- TODO: add a 30-45 s demo GIF at docs/assets/demo.gif (proxy-status -> proxy-disable preview -> dns-edge-fix preview), then replace this comment with:
     ![wnrt demo](docs/assets/demo.gif) -->

## What it diagnoses and fixes

| Symptom | What WNRT checks | Commands |
|---|---|---|
| Browser shows `ERR_PROXY_CONNECTION_FAILED`, but ping and DNS work | WinINET and WinHTTP proxy settings, read side by side. Flags a proxy that points at a localhost port where nothing is listening (`DEAD_PROXY_CONFIG`, `DEAD_LOCALHOST_PORT`) and WinINET/WinHTTP disagreeing (`WININET_WINHTTP_MISMATCH`). Finds which process owns a localhost proxy listener. | `proxy-status`, `proxy-health`, `proxy-owner`, `proxy-disable` |
| Proxy setting keeps coming back after you turn it off | Polls the proxy settings for drift and replays the recorded changes through a state machine that classifies each transition and flags on/off loops (`REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP`). | `proxy-watch`, `proxy-replay` |
| `ERR_NAME_NOT_RESOLVED` in Edge while other apps work | DNS servers on the adapter, Edge secure-DNS / built-in resolver policy, and (with `--url`) the site's own nameservers, to tell a local problem from a broken domain. | `dns-edge-status`, `dns-edge-fix` |
| Some sites hang or tabs keep loading; IPv4 works, IPv6 doesn't | IPv4 vs IPv6 HTTPS reachability across several hosts. Can preview or apply Windows' "prefer IPv4" setting, and undo it. | `ipv6-path-status`, `ipv6-path`, `ipv6-prefer-ipv4`, `ipv6-restore-preference` |
| "Something is broken, not sure what" | Combines the proxy, DNS/Edge and IPv6 checks, ranks the likely causes, and prints the next command to run. | `why-broken [--url <page>]` |

Evidence can be shared without exposing the machine: `evidence/redaction.py` replaces IPv4, IPv6 and MAC addresses, and fields such as hostname or VPN endpoint, with stable hashed tokens (for example `<ipv4:06418959d062ac18>`), so records stay comparable without the raw values.

The live checks and fixes run on Windows. On other systems they report `unsupported_platform`, but the fixture-based commands in the quickstart below run anywhere.

## Safety model

- **Preview by default.** `proxy-disable`, `dns-edge-fix`, `ipv6-prefer-ipv4` and `ipv6-restore-preference` default to `--dry-run true`. They print the planned changes and make none.
- **Typed confirmation to apply.** A live change needs `--dry-run false` plus an exact, case-sensitive token: `DISABLE_WININET_PROXY`, `FIX_ERR_NAME_NOT_RESOLVED`, `PREFER_IPV4_OVER_IPV6` or `RESTORE_IPV6_PREFERENCE`. A missing or wrong token blocks the change.
- **Administrator only where Windows requires it.** Changing DNS servers or the IPv6 preference (HKLM) needs an elevated shell; without one the command stops with `needs_elevation`. The proxy fix only changes the current user's WinINET settings (HKCU).
- **Undo path.** Output records the previous values (`before`, `dns_servers_before`). `ipv6-restore-preference` reverses the IPv4 preference. DNS can be returned to DHCP with `Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses`.
- **Audit trail.** Every preview and apply is appended to a local JSONL log under `.audit/`.
- **Never done:** killing processes, resetting the firewall, disabling adapters, or modifying WinHTTP settings.

Details: [docs/safety_model.md](docs/safety_model.md).

## Quickstart

Requires Python 3.11+.

```powershell
git clone https://github.com/Kozphy/windows-network-recovery-toolkit-public.git
cd windows-network-recovery-toolkit-public
python -m venv .venv
.venv\Scripts\Activate.ps1        # macOS/Linux: source .venv/bin/activate
pip install -e .
```

These three commands use sample data bundled in the repo, so they work on any OS and don't touch your system. Output below is from a real run, trimmed where marked with `...`.

**1. Classify a dead localhost proxy**

```text
$ wnrt proxy-status --fixture examples/evidence/DEAD_PROXY_CONFIG.json
{
  "wininet": {
    "ProxyEnable": 1,
    "ProxyServer": "127.0.0.1:59081",
    ...
  },
  "winhttp": {
    "direct_access": true,
    ...
  },
  "localhost_port": 59081,
  "classification": "DEAD_PROXY_CONFIG",
  "classification_result": {
    "primary_classification": "DEAD_PROXY_CONFIG",
    "secondary_signals": [
      "WININET_WINHTTP_MISMATCH",
      "DEAD_LOCALHOST_PORT"
    ],
    "severity": "medium",
    "reasoning": "WinINET references localhost:59081 but no listener is bound.",
    ...
```

**2. Compare the proxy path with the direct path**

```text
$ wnrt proxy-health --fixture tests/fixtures/proxy_health_dead.json
=== Proxy path diagnosis (read-only) ===

WinINET state:
  ProxyEnable: 1
  ProxyServer: 127.0.0.1:59081
  Localhost proxy configured: yes
  Parsed localhost port: 59081

TCP / listener:
  TCP listener attributed: no

Path probes:
  Proxy HTTPS probe: failed
  Direct HTTPS probe: ok

Classification: DIRECT_ONLY_WORKS
Incident class: DEAD_PROXY_CONFIG
Risk: HIGH
Recommended policy action: block_or_disable_preview

Interpretation: Direct internet works but configured localhost proxy path fails.
Failure reason: No listener
...
```

**3. Replay a proxy setting that keeps flipping back**

```text
$ wnrt proxy-replay --input tests/fixtures/proxy_transitions/proxy_enable_flapping_loop.jsonl --format human
Replay: 5 input rows -> 5 classified events
{
  "event_id": "c099b7867431431fb4567318",
  "timestamp_utc": "2026-01-01T00:00:00Z",
  ...
  "transition_class": "LOCALHOST_PROXY_ENABLED",
  "risk": "MEDIUM",
  ...
}
... (4 more events, one JSON block each)

CTRL_PROXY_CLASSIFICATION_ACCURACY: PASS
CTRL_ATTRIBUTION_PROOF_BOUNDARY: PASS
CTRL_POLICY_GATE_NO_AUTONOMOUS_REMEDIATION: PASS
CTRL_AUDIT_REPLAY_DETERMINISM: PASS
CTRL_COALESCING_REDUCES_FALSE_ALERTS: PASS
CTRL_REVERTER_LOOP_PATTERN_DETECTION: PASS
```

The five events are classified `LOCALHOST_PROXY_ENABLED` → `PROXY_DISABLED_AND_SERVER_REMOVED` → `LOCALHOST_PROXY_ENABLED` → `PROXY_DISABLED_AND_SERVER_REMOVED` → `REVERTER_SUSPECTED_LOCALHOST_PROXY_LOOP` (risk HIGH): something keeps turning the localhost proxy back on.

### On a Windows PC

Run the same commands without `--fixture` to read the live machine. A good starting point is `wnrt why-broken --url <failing page>`, which ranks the likely causes and prints the next command. Fix commands (`proxy-disable`, `dns-edge-fix`, `ipv6-prefer-ipv4`) only preview until you add `--dry-run false --confirm <TOKEN>`.

Runbooks: [why-broken](docs/runbooks/why-broken.md) · [DNS / ERR_NAME_NOT_RESOLVED](docs/runbooks/dns-edge-err-name-not-resolved.md) · [IPv6 blackhole](docs/runbooks/ipv6-path-blackhole.md) · [dead proxy guardian](docs/dead-proxy-guardian.md) · [troubleshooting flow](docs/troubleshooting_flow.md)

## Tests

```bash
pip install -e ".[dev]"
python -m pytest -q tests/test_policy_safety_contract.py tests/test_api_dry_run_default.py \
  tests/windows_network_toolkit/test_dns_edge.py tests/windows_network_toolkit/test_ipv6_path.py
```

CI runs the public safety slice on every push and pull request: [.github/workflows/public-mirror-ci.yml](.github/workflows/public-mirror-ci.yml).

## Other modules

This repository is a public mirror of a larger private project, so `wnrt --help` also lists commands outside network troubleshooting (risk analytics, LAN inventory, email/website risk, reporting exports) and the repo includes a read-only fixture-mode demo API and frontend. They aren't needed for anything above. See [docs/PLATFORM_OVERVIEW.md](docs/PLATFORM_OVERVIEW.md) for the demo API and frontend, and [docs/private-public-split.md](docs/private-public-split.md) for what is and isn't published.

This is a diagnostic tool, not antivirus or EDR. Its classifications are observations, not proof of malware or attack.

## Need help with a Windows network issue?

If a PC or small office is stuck with proxy, DNS, VPN or "connected but no internet" problems, I can diagnose and fix it remotely using this approach: find the cause first, preview the change, then apply it with a way back.

**Hire me on Upwork:** https://www.upwork.com/freelancers/~01f2d28a00fa4262d3

## License

AGPL-3.0-only. See [LICENSE](LICENSE).

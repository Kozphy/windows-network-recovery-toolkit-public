# Security Policy

## Supported versions

Security-relevant fixes apply to the latest commit on the default branch. This is a **local-first diagnostic prototype**, not a commercially supported product.

## Reporting a vulnerability

If you discover a security issue in this repository:

1. **Prefer private disclosure** — open a GitHub **Security Advisory** (Private vulnerability report) if enabled, or email the maintainer if listed in the repository profile.
2. Include: affected module, reproduction steps, impact, and suggested mitigation.
3. **Do not** attach real machine logs, internal hostnames, live proxy URLs, tokens, or corporate network details.

Placeholder contact: use GitHub Security Advisories for this repository until a dedicated security email is published.

---

## What this project is

- A **diagnostic and remediation-preview** toolkit for Windows endpoint reliability (proxy, DNS, browser path, network layers).
- A **policy-gated** system with append-only audit logs and deterministic replay from stored observations.

## What this project is not

- **Not antivirus** or malware removal software.
- **Not EDR** or autonomous containment.
- **Not a silent auto-repair agent** — destructive or high-risk actions require explicit operator confirmation and remain blocked or manual-only by default.

---

## Safety boundaries

The toolkit must **not**:

- Kill processes silently.
- Reset firewall or disable network adapters without explicit, typed operator confirmation.
- Mutate registry keys outside allowlisted preview/execute flows.
- Upload logs or telemetry to the cloud **by default** (optional agent ingest is opt-in).
- Collect or store credentials.
- Bypass enterprise policy or disable security products.

Live repair paths that exist in the prototype are **allowlisted**, **audited**, and default to **dry-run**.

---

## Evidence and proof limits

- **Listener / process correlation is not proof** of registry-writer identity.
- **Strong registry-writer attribution** requires telemetry such as Sysmon registry events, Security 4657, or imported Procmon traces — otherwise status remains inference or unavailable.
- **Confidence scores** in JSON output are ordinal ranking weights, not calibrated probabilities.

See [docs/adr/ADR-004-heuristic-attribution-is-not-proof.md](docs/adr/ADR-004-heuristic-attribution-is-not-proof.md).

---

## Privacy before sharing logs

Diagnostic output may contain:

- Internal hostnames or hashed endpoint identifiers
- Proxy URLs and ports
- Process paths
- Redacted or raw IP addresses

**Review and redact** before posting issues or portfolio snippets. Do not upload private `logs/`, `reports/`, or `platform_data/` exports to public trackers.

Run `python tools/public_release_audit.py --tracked-only` before publishing forks. Use `--include-untracked` for a full local hygiene scan. See [PUBLIC_RELEASE_CHECKLIST.md](PUBLIC_RELEASE_CHECKLIST.md).

---

## Responsible use

- Run with least privilege; Administrator is required only for specific stop-listener/reverter flows documented in the CLI reference.
- Treat preview output as **operator guidance**, not autonomous remediation.
- Validate policy decisions in your environment before any live execute.

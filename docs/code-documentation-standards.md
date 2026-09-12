# Code Documentation Standards

Canonical documentation rules for this repository. Apply when adding or upgrading docstrings, comments, and operational script headers.

**Domain (verified):** Technology Risk & Control Analytics for Windows endpoint proxy reliability — evidence collection, classification, control tests, policy-gated remediation previews, audit JSONL, and governance exports. **Not** antivirus, EDR, autonomous remediation, or malware verdicts.

---

## Python — Google-style docstrings

### Module docstring

Open with a one-line summary, then optional structured sections:

```text
Module responsibility:
    What this module owns.

System placement:
    Callers, CLI commands, or API routes that use it.

Key invariants:
    Rules that must not be violated (e.g. read-only, full-state classification).

Side effects:
    File writes, registry reads/writes, network probes, subprocesses.

Failure modes:
    Common errors and how they surface.

Audit Notes:        (critical paths only)
    What could go wrong, detection, recovery, evidence available.

Engineering Notes:  (non-trivial trade-offs only)
    Why this design; alternatives rejected.
```

### Public class / enum

- Summary line
- Variant or field semantics
- Invariants and limitations (e.g. forbidden labels when `ProxyServer` empty)

### Public function

```text
Summary line.

Args:
    name: Description.

Returns:
    Description of return value and shape.

Raises:
    ExceptionType: When raised.

Side effects:
    Explicit list or "None".

Examples:
    Optional minimal example.

Audit Notes:
    (mutations, policy gates, classification decisions only)
```

### Decision / classification logic

Document additionally:

- **Decision intent** — what question the function answers
- **Inputs used** — full before/after state vs single-field diff
- **Constraints** — proof tiers, safety frozensets
- **Verification** — pytest module or fixture path
- **Recovery** — what to do if output is wrong (re-run replay, collect Sysmon E13)

---

## Evidence-based wording

| Use | Avoid |
|-----|-------|
| observation, hypothesis, proof tier, triage label | malware detected, compromise confirmed |
| correlation, pattern suggests | proves causality, guaranteed safe |
| preview-only, policy decision | autonomous fix, AI-authorized execution |
| management information | formal audit opinion |
| limitations[] | certainty, probability of attack |

---

## TypeScript / JavaScript — TSDoc

Follow [`frontend/lib/api.ts`](../frontend/lib/api.ts):

- `@param`, `@returns`, `@throws`
- `@remarks` for side effects and idempotency
- `@file` module summary when the file is a shared client

---

## PowerShell / Batch — safety headers

At file top (comment-based help or `REM` blocks):

```text
# Purpose:
# Privileges:
# Inputs:
# Outputs:
# Side effects:
# Idempotency:
# Recovery:
# SAFETY: (read-only vs mutating; typed confirmation if mutating)
```

---

## Critical paths (Audit Notes required)

- Proxy transition classification (`classify_transition`, `validate_classification_safety`)
- Registry mutation (`proxy_remediation`, `cmd_proxy_disable`)
- Policy evaluation (`evaluate_policy`)
- Audit append / hash chain (`audit_store`)
- Blocked destructive actions (`safety.py`)

---

## What not to document

- Private `_` helpers unless they encode non-obvious assumptions
- Test modules unless shared fixture utilities are public API
- Generated export CSVs
- Speculative production deployment, SaaS, or monitoring not present in code

---

## Verification after documentation changes

```powershell
pytest -q tests/test_proxy_state_transitions.py tests/test_proxy_classifier_safety_contract.py
pytest -q
ruff check <touched-paths>
```

Do not change argparse `help=` strings unless behavior intentionally changes.

---

## Related

- [ONBOARDING.md](ONBOARDING.md) — 10-minute repository map
- [runbooks/ipv6-path-blackhole.md](runbooks/ipv6-path-blackhole.md) — IPv6 blackhole + prefer/restore IPv4
- [runbooks/dns-edge-err-name-not-resolved.md](runbooks/dns-edge-err-name-not-resolved.md) — DNS/Edge ERR_NAME_NOT_RESOLVED
- [test-strategy.md](test-strategy.md) — fixture and safety contract tests
- [adr/0007-proxy-transition-full-state-classification.md](adr/0007-proxy-transition-full-state-classification.md)

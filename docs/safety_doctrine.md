# Safety Doctrine

## Core rules

1. **Observation is not proof** — registry values and probes are facts at time T, not causation.
2. **Correlation is not causation** — listener ownership is candidate evidence only.
3. **Confidence is not certainty** — scores rank hypotheses; they are not calibrated probabilities.
4. **Policy permission is not a safety guarantee** — ALLOW/PREVIEW still requires operator judgment.

## Blocked without confirmation

- Registry mutation
- Process kill
- Firewall reset
- Adapter disable
- Automatic proxy disable

## API defaults

- `dry_run=true` on all remediation execute paths
- Typed confirmation phrases for allowlisted actions only

## AI boundary (future)

AI may recommend narrative explanations. AI must not call remediation execute or mutate host state.

See also: [epistemic_model.md](epistemic_model.md), [safety_model.md](safety_model.md)

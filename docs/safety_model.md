# Safety model (legacy — extended)

**Canonical summary:** [safety-model.md](safety-model.md)

This file retains extended operator guidance. See canonical doc for gate definitions and CI contracts.

---

# Safety Model (extended)

This project is designed for beginner users, so safety is more important than aggressive repair.

## Allowed by default (read-only)

- Read WinINET / WinHTTP registry and `netsh` excerpts  
- Run proxy health probes and path contrasts  
- Classify evidence and generate governance reports  
- Export CSV / Power BI star-schema tables  
- Verify audit hash chains and replay fixtures  

## Blocked by default

- Registry mutation without typed confirmation  
- Live `proxy-disable` apply without dry-run review  
- Process kill, firewall reset, adapter disable  
- Autonomous remediation narratives  
- Malware / MITM verdicts without limitations  
- AI-authorized execution  

See [safety-model.md](safety-model.md) for the canonical safety model.

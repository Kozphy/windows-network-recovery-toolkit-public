"""Domain/Network Provenance — read-only operator-country evidence pipeline.

Module responsibility:
    Expose ``run_domain_provenance`` for fixture-first (and optional online)
    assessment of domain operator vs infrastructure geography.

System placement:
    CLI: ``domain-provenance``. Isolated from proxy/DNS/IPv6 recovery flows.

Key invariants:
    * Infrastructure countries never determine operator country.
    * Online RDAP.org / country.is require explicit ``online=True``.
    * IPs redacted by default in console and audit payloads.
    * Policy always requires human review; never authorizes remediation.

Side effects:
    Optional soft-append to ``.audit/domain-provenance.jsonl``.

Audit Notes:
    Observation ≠ ownership proof; hosting location ≠ operator country.
"""

from __future__ import annotations

from windows_network_toolkit.provenance.pipeline import run_domain_provenance

__all__ = ["run_domain_provenance"]

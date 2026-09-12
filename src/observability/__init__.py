"""Windows host observability probes (explicit submodule imports only).

Module responsibility:
    Package marker for read-only LAN and protocol probes under ``src.observability``.

System placement:
    Consumers import ``lan_neighbor``, ``mdns_probe``, or ``ssdp_probe`` directly —
    not via eager re-exports from this ``__init__``.

Key invariants:
    * No symbols re-exported here to avoid circular import during toolkit init.
    * All probes are observation-only; remediation lives elsewhere.

Side effects:
    * None at import time.
"""

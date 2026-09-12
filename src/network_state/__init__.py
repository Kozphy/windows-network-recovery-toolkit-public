"""Network State Manager package.

Coordinates named proxy posture snapshots (:mod:`snapshot_store`), deterministic drift overlays
(:mod:`diff_engine`, :mod:`policy`), append-only auditing (:mod:`audit`, :mod:`events`),
and CLI glue in ``cli_handlers``. Operates beside legacy ``proxy-snapshot`` while persisting parallel JSONL sinks.

Important:
    Operators must reconcile explicit restore confirms — this package never silently mutates adapters or firewall stacks.

"""

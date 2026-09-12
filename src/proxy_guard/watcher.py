"""Read-only HKCU proxy registry polling for lightweight monitor tooling.

Module responsibility:
    Poll Internet Settings, normalize registry views, print diffs, and optionally
    append JSONL events — no attribution merge or rollback.

System placement:
    Used by legacy monitor paths and tests; superseded for rich attribution by
    ``proxy-watch`` / :mod:`guard` in most operator flows.

Key invariants:
    * **Never** writes registry keys or invokes rollback helpers.
    * ``port_owner_fn`` is optional enrichment when localhost ports parse.

Side effects:
    Optional append to caller-supplied ``jsonl_path``; stdout/stderr prints only.

Idempotency:
    Each poll is independent; prior snapshot held in memory for diff only.

Audit Notes:
    Rows may use schema v1 ``proxy_state_change`` — normalize on read via
    :mod:`flip_flop` before incident analysis.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..core.jsonl import append_jsonl
from ..proxy_guard.parser import parse_proxy_server
from ..proxy_guard.registry import read_proxy_registry
from .events import proxy_guard_event
from .planning import normalize_registry_view


def monitor_proxy_registry(
    *,
    interval: float,
    once: bool,
    jsonl_path: Path | None,
    emit_json_stdout: bool,
    port_owner_fn: Callable[[int | None], dict[str, Any]] | None = None,
    run: Any = None,
) -> None:
    """Poll registry; print changes and optionally append JSONL events.

    No automatic registry writes are performed.
    """
    import subprocess

    run_fn = run or subprocess.run
    prior: dict[str, Any] | None = None
    while True:
        snap = read_proxy_registry(run=run_fn)
        reg_d = snap.to_dict()
        parsed = parse_proxy_server(snap.proxy_server)
        view = normalize_registry_view(reg_d, parsed.to_dict())
        if prior is not None and json.dumps(prior, sort_keys=True) != json.dumps(view, sort_keys=True):
            msg = "[proxy-monitor] registry change detected"
            print(msg, file=sys.stderr)
            print(json.dumps(view, indent=2, ensure_ascii=False))
            owners_payload: dict[str, Any] = {}
            if port_owner_fn and parsed.is_localhost_proxy and parsed.localhost_port:
                owners_payload = port_owner_fn(parsed.localhost_port)
            if jsonl_path:
                ev = proxy_guard_event(
                    event_type="registry_change",
                    registry_view=view,
                    owners=owners_payload,
                )
                append_jsonl(jsonl_path, ev)
        elif prior is None:
            print(json.dumps(view, indent=2, ensure_ascii=False))
            if jsonl_path:
                append_jsonl(
                    jsonl_path,
                    proxy_guard_event(event_type="initial", registry_view=view),
                )
        prior = view
        if once:
            return
        time.sleep(max(1.0, interval))

"""Layered merge of Sysmon / Procmon / listener / heuristic evidence for HKCU proxy transitions.

Module responsibility:
    Collect registry diff excerpts, optional Sysmon EID 13 rows, Procmon imports,
    localhost listener owners, and process-inventory heuristics; rank a single
    ``candidate_actor`` without claiming registry-writer proof.

System placement:
    Invoked from :mod:`guard` on substantive WinINET changes; complements read-only
    :mod:`evidence_import` CSV boosts on ``proxy-watch``.

Key invariants:
    * Baseline limitation strings always include ``registry polling cannot prove exact writer``.
    * Sysmon wins over listener correlation when high-confidence EID 13 rows match proxy keys.

Input assumptions:
    ``before`` / ``after`` dicts mirror :class:`~models.ProxySnapshot` fields; Windows
    for live Sysmon queries.

Output guarantees:
    :class:`~attribution_model.LayeredAttributionResult` with evidence list suitable for
    JSONL audit append.

Failure modes:
    Missing telemetry yields zero-score evidence rows — not exceptions.

Audit Notes:
    Label operator banners ``ListenerCorrelation (not RegistryWriterProof)`` unless
    Sysmon path sets ``attribution_method=sysmon_event_13``.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import Any, cast

from .attribution_model import (
    AttributionEvidence,
    LayeredAttributionResult,
    ProxyActor,
)
from .listener_attribution import attribute_localhost_proxy_listener
from .process_inventory import collect_recent_process_inventory, heuristic_proxy_actor_candidates
from .procmon_import import load_procmon_proxy_events
from .sysmon_attribution import collect_sysmon_proxy_events

_BASELINE_NOTES = (
    "best-effort attribution only",
    "registry polling cannot prove exact writer process",
)


def _registry_diff_excerpt(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    keys = ("proxy_enable", "proxy_server", "auto_config_url", "auto_detect", "proxy_override")
    out: dict[str, Any] = {"changed_fields": []}
    for k in keys:
        ob, nb = old.get(k), new.get(k)
        if ob != nb:
            out["changed_fields"].append(k)
            out[f"{k}_before"] = ob
            out[f"{k}_after"] = nb
    return out


def _image_basename(image: str | None) -> str | None:
    if not isinstance(image, str) or not image.strip():
        return None
    s = image.strip().replace("/", "\\")
    return s.rsplit("\\", 1)[-1] or None


def _actor_from_sysmon(ev: AttributionEvidence) -> ProxyActor | None:
    raw = ev.raw_excerpt or {}
    pid = raw.get("process_id")
    pid_i = int(pid) if isinstance(pid, int) else (int(pid) if isinstance(pid, str) and pid.strip().isdigit() else None)
    if pid_i is None:
        return None
    img = raw.get("image")
    usr = raw.get("user")
    img_s = str(img).strip() if isinstance(img, str) and img.strip() else None
    return ProxyActor(
        pid=pid_i,
        process_name=_image_basename(img_s),
        image_path=img_s,
        command_line=None,
        user=str(usr).strip() if isinstance(usr, str) and usr.strip() else None,
        parent_pid=None,
        parent_process_name=None,
        signer=None,
        started_at=None,
    )


def _actor_from_procmon(ev: AttributionEvidence) -> ProxyActor | None:
    raw = ev.raw_excerpt or {}
    pid = raw.get("pid")
    pid_i = int(pid) if isinstance(pid, int) else (int(pid) if isinstance(pid, str) and str(pid).isdigit() else None)
    if pid_i is None:
        return None
    pname = str(raw.get("process_name") or "").strip()
    return ProxyActor(
        pid=pid_i,
        process_name=pname or None,
        image_path=None,
        command_line=None,
    )


def attribute_proxy_change(
    old_snapshot: dict[str, Any],
    new_snapshot: dict[str, Any],
    *,
    since_seconds: int = 60,
    evidence_csv: str | None = None,
    run: Callable[..., Any] | None = None,
) -> LayeredAttributionResult:
    """Correlate a registry snapshot transition with layered evidence tiers (observability only).

    Priority for **winner** actor selection (non-exclusive — all tiers append to ``evidence``):
        Sysmon Event 13 proxy key → Procmon CSV RegSetValue → localhost listener PID → heuristic CIM lexicon →
        unknown fallback.

    Args:
        old_snapshot: Prior ``normalize_registry_view``-shaped dictionary (scalar HKCU snapshot fields).
        new_snapshot: Current view in identical shape after drift.
        since_seconds: Look-back window for Sysmon / rough Procmon time gate.
        evidence_csv: Optional Procmon CSV path.
        run: ``subprocess.run`` surrogate (defaults to stdlib).

    Returns:
        :class:`~src.proxy_guard.attribution_model.LayeredAttributionResult` suitable for audit export.

    Side effects:
        May spawn PowerShell collectors (Sysmon, CIM) when ``run`` is live — never mutates proxy keys here.
    """
    subprocess_run = run if run is not None else subprocess.run

    diff_excerpt = _registry_diff_excerpt(old_snapshot, new_snapshot)
    aggregated: list[AttributionEvidence] = [
        AttributionEvidence(
            source="registry_polling",
            confidence_score=0.0,
            raw_excerpt=dict(diff_excerpt),
            notes=list(_BASELINE_NOTES)
            + [
                (
                    "Registry polling detected configuration delta between polls"
                    if diff_excerpt["changed_fields"]
                    else "No scalar proxy field deltas between normalized snapshots"
                ),
            ],
        ),
    ]

    sysmon_block = collect_sysmon_proxy_events(since_seconds=since_seconds, run=subprocess_run)
    aggregated.extend(sysmon_block)

    if evidence_csv:
        aggregated.extend(load_procmon_proxy_events(evidence_csv, since_seconds=since_seconds))

    proxy_server_after = new_snapshot.get("proxy_server")
    listener_layer = attribute_localhost_proxy_listener(
        proxy_server_after if isinstance(proxy_server_after, str) else None,
        run=subprocess_run,
    )
    aggregated.extend(listener_layer.evidence)

    inv = collect_recent_process_inventory(limit=30, run=subprocess_run)
    heur_candidates = heuristic_proxy_actor_candidates(inv)
    if heur_candidates:
        top = heur_candidates[0]
        aggregated.append(
            AttributionEvidence(
                source="process_inventory_heuristic",
                confidence_score=0.28,
                raw_excerpt=top.to_jsonable(),
                notes=[
                    "Recent Win32_Process row matched developer/proxy lexical heuristics",
                    "Low confidence — unrelated processes may coincidentally match substrings",
                ],
            ),
        )
    else:
        aggregated.append(
            AttributionEvidence(
                source="process_inventory_heuristic",
                confidence_score=0.0,
                notes=["No heuristic process_inventory candidate matched curated substrings"],
            ),
        )

    winner_actor: ProxyActor | None = None
    winner_confidence: str = "unknown"
    winner_method = "unknown"

    # 1) Sysmon matched proxy-value SetValue
    for ev in aggregated:
        if (
            getattr(ev, "source", "") == "sysmon_event_13"
            and ev.confidence_score >= 0.8
            and ev.raw_excerpt
        ):
            actor = _actor_from_sysmon(ev)
            if actor is not None:
                winner_actor, winner_confidence, winner_method = actor, "high", "sysmon_event_13"
                break

    # 2) Procmon CSV successes (ignore diagnostic-only rows below threshold)
    if winner_actor is None:
        best_pc: AttributionEvidence | None = None
        best_actor: ProxyActor | None = None
        for ev in aggregated:
            if ev.source != "procmon_csv" or ev.confidence_score < 0.6:
                continue
            actor = _actor_from_procmon(ev)
            if actor is None:
                continue
            if best_pc is None or ev.confidence_score > best_pc.confidence_score:
                best_pc = ev
                best_actor = actor
        if best_actor is not None and best_pc is not None:
            winner_actor = best_actor
            winner_confidence = "high" if best_pc.confidence_score >= 0.85 else "medium"
            winner_method = "procmon_csv"

    # 3) Local listener (does not imply writer)
    if winner_actor is None and listener_layer.candidate_actor is not None:
        pid_ok = listener_layer.candidate_actor.pid is not None
        if pid_ok and listener_layer.attribution_confidence == "medium":
            winner_actor = listener_layer.candidate_actor
            winner_confidence = "medium"
            winner_method = "localhost_listener"

    # 4) Heuristic inventory
    if winner_actor is None and heur_candidates:
        winner_actor = heur_candidates[0]
        winner_confidence = "low"
        winner_method = "process_inventory_heuristic"

    notes_tail = list(dict.fromkeys((*_BASELINE_NOTES, *listener_layer.attribution_notes)))
    return LayeredAttributionResult(
        candidate_actor=winner_actor,
        attribution_confidence=winner_confidence,  # type: ignore[arg-type]
        attribution_method=winner_method,
        evidence=aggregated,
        attribution_notes=notes_tail,
    )


def layered_to_heuristic_pipeline(layered: LayeredAttributionResult):
    """Map layered merge output onto :class:`~src.proxy_guard.models.HeuristicPipelineAttribution` audits."""

    from .models import ActorCandidate, HeuristicAttributionConfidence, HeuristicPipelineAttribution

    score_rank = {"high": 100, "medium": 82, "low": 54, "unknown": 0}
    ca = layered.candidate_actor
    cand: ActorCandidate | None = None
    conf = layered.attribution_confidence
    if ca is not None and isinstance(ca.pid, int):
        score_v = score_rank.get(str(conf), 0)
        if score_v <= 0:
            score_v = 55 if conf not in {"unknown"} else 0
        cand = ActorCandidate(
            pid=ca.pid,
            process_name=str(ca.process_name or "unknown.exe").strip() or "unknown.exe",
            process_path=ca.image_path,
            parent_pid=ca.parent_pid,
            command_line=ca.command_line,
            score=min(100, max(score_v, 1)) if str(conf) != "unknown" else max(score_v, 0),
            reasons=tuple(layered.attribution_notes[:12]) or ("layered_attribution_merge",),
        )
    attrib_conf = cast(HeuristicAttributionConfidence, "unknown" if cand is None else str(conf))
    evid = tuple(ev.to_jsonable() for ev in layered.evidence)
    return HeuristicPipelineAttribution(
        candidate_actor=cand,
        attribution_confidence=attrib_conf,
        attribution_method=str(layered.attribution_method),
        attribution_notes=tuple(dict.fromkeys((*_BASELINE_NOTES, *layered.attribution_notes))),
        evidence=evid,
    )

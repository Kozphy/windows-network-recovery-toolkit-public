"""Generate structured incident reviews from case studies or platform data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class IncidentReview(BaseModel):
    """Represent IncidentReview data or behavior for toolkit workflows.

    Attributes:
        Values are defined by the dataclass, model fields, or initializer.

    Limitations:
        Represents observed or configured state, not a certainty claim.
    """

    incident_id: str
    title: str
    status: str = "resolved"
    severity: str = "medium"
    evidence_level: str
    policy_gate: str
    proof_status: str
    impact: list[str] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    root_cause: str
    limitations: list[str] = Field(default_factory=list)
    follow_up_actions: list[str] = Field(default_factory=list)
    epistemic_notes: list[str] = Field(default_factory=list)


def _repo_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    return Path(__file__).resolve().parents[2]


def resolve_case_study_dir(incident_id: str, *, repo_root: Path | None = None) -> Path | None:
    """Resolve ``case_studies/<id>/`` when present."""
    root = _repo_root(repo_root)
    direct = root / "case_studies" / incident_id
    if direct.is_dir():
        return direct
    for child in (root / "case_studies").glob("*"):
        if child.is_dir() and (child.name == incident_id or child.name.endswith(incident_id)):
            return child
    return None


def list_case_study_ids(*, repo_root: Path | None = None) -> list[str]:
    """List case study ids for toolkit workflows.

    Args:
        repo_root: Value supplied by the caller for repo root.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    root = _repo_root(repo_root)
    base = root / "case_studies"
    if not base.is_dir():
        return []
    return sorted(p.name for p in base.iterdir() if p.is_dir())


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return blob if isinstance(blob, dict) else {}


def _parse_timeline_md(text: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or stripped.startswith("| ---"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) >= 3 and cells[0].lower() not in ("time (utc)", "time"):
            events.append({"time_utc": cells[0], "event": cells[1], "detail": cells[2]})
    return events


def _load_case_study(case_dir: Path) -> IncidentReview:
    incident_id = case_dir.name
    readme = (
        (case_dir / "README.md").read_text(encoding="utf-8")
        if (case_dir / "README.md").is_file()
        else ""
    )
    title = incident_id.replace("_", " ").title()
    for line in readme.splitlines():
        if line.startswith("# "):
            title = line[2:].strip()
            break

    evidence = _load_json(case_dir / "evidence_tree.json")
    policy = _load_json(case_dir / "policy_decision.json")
    review_md = (
        (case_dir / "incident_review.md").read_text(encoding="utf-8")
        if (case_dir / "incident_review.md").is_file()
        else ""
    )

    timeline_path = case_dir / "timeline.md"
    if timeline_path.is_file():
        timeline = _parse_timeline_md(timeline_path.read_text(encoding="utf-8"))
    else:
        timeline = evidence.get("timeline") or []

    impact: list[str] = []
    limitations: list[str] = []
    follow_up: list[str] = []
    root_cause = policy.get("root_cause") or evidence.get("root_cause") or "See case study README."
    for section, bucket in (
        ("## Impact", impact),
        ("## Limitations", limitations),
        ("## Follow-up", follow_up),
        ("## Follow-up actions", follow_up),
    ):
        if section in review_md:
            chunk = review_md.split(section, 1)[1].split("##", 1)[0]
            for line in chunk.splitlines():
                line = line.strip()
                if line.startswith("- "):
                    bucket.append(line[2:].strip())

    return IncidentReview(
        incident_id=incident_id,
        title=title,
        status=str(policy.get("status") or "resolved"),
        severity=str(policy.get("severity") or policy.get("policy_severity") or "medium"),
        evidence_level=str(
            evidence.get("evidence_level") or evidence.get("level") or "correlation"
        ),
        policy_gate=str(policy.get("gate") or policy.get("decision") or "preview"),
        proof_status=str(evidence.get("proof_status") or policy.get("proof_status") or "partial"),
        impact=impact or list(evidence.get("impact") or []),
        timeline=timeline if isinstance(timeline, list) else [],
        root_cause=str(root_cause),
        limitations=limitations or list(evidence.get("limitations") or []),
        follow_up_actions=follow_up or list(policy.get("follow_up_actions") or []),
        epistemic_notes=[
            "Observation ≠ proof — registry-writer claims require Sysmon/Procmon-class telemetry.",
            "Correlation ≠ causation — listener port alignment is candidate evidence only.",
            "Policy PREVIEW / require_confirmation ≠ autonomous remediation approval.",
        ],
    )


def generate_incident_review(
    incident_id: str,
    *,
    repo_root: Path | None = None,
    data_root: Path | None = None,
) -> IncidentReview:
    """Build review from ``case_studies/`` first, else platform JSONL hints."""
    case_dir = resolve_case_study_dir(incident_id, repo_root=repo_root)
    if case_dir is not None:
        return _load_case_study(case_dir)

    from platform_core.storage import iter_jsonl, platform_data_dir

    root = data_root or platform_data_dir()
    for row in iter_jsonl(root / "failure_events.jsonl"):
        if str(row.get("event_id") or row.get("id") or "") == incident_id:
            return IncidentReview(
                incident_id=incident_id,
                title=str(row.get("title") or row.get("category") or incident_id),
                status=str(row.get("status") or "open"),
                severity=str(row.get("severity") or "medium"),
                evidence_level=str(row.get("evidence_level") or "observation"),
                policy_gate=str(row.get("policy_gate") or "preview"),
                proof_status=str(row.get("proof_status") or "unavailable"),
                impact=[str(row.get("summary") or "Platform failure event")],
                timeline=[
                    {
                        "time_utc": row.get("timestamp"),
                        "event": row.get("category"),
                        "detail": row.get("summary"),
                    }
                ],
                root_cause=str(
                    row.get("root_cause") or "Undetermined — collect proxy forensics bundle."
                ),
                limitations=[
                    "Generated from platform_data failure_events.jsonl — not a full case study."
                ],
                follow_up_actions=["Run proxy-causation --fixture or ingest Sysmon proof layer."],
            )
    raise FileNotFoundError(f"No case study or platform incident for id={incident_id!r}")


def render_incident_review_markdown(review: IncidentReview | dict[str, Any]) -> str:
    """Render incident review markdown for toolkit workflows.

    Args:
        review: Value supplied by the caller for review.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    model = review if isinstance(review, IncidentReview) else IncidentReview.model_validate(review)
    lines = [
        f"# Incident review: {model.title}",
        "",
        f"**Incident ID:** `{model.incident_id}`",
        f"**Status:** {model.status} · **Severity:** {model.severity}",
        f"**Evidence level:** {model.evidence_level} · **Policy gate:** {model.policy_gate}",
        f"**Proof status:** {model.proof_status}",
        "",
        "## Impact",
    ]
    lines.extend(f"- {item}" for item in model.impact) or lines.append("- (none recorded)")
    lines.extend(["", "## Timeline", "", "| Time (UTC) | Event | Detail |", "| --- | --- | --- |"])
    for ev in model.timeline:
        lines.append(
            f"| {ev.get('time_utc', '')} | {ev.get('event', '')} | {ev.get('detail', '')} |"
        )
    lines.extend(
        [
            "",
            "## Root cause",
            "",
            model.root_cause,
            "",
            "## Policy decision",
            "",
            f"Gate: **{model.policy_gate}**",
        ]
    )
    lines.extend(["", "## Limitations"])
    lines.extend(f"- {item}" for item in model.limitations)
    lines.extend(["", "## Follow-up actions"])
    lines.extend(f"- {item}" for item in model.follow_up_actions)
    lines.extend(["", "## Epistemic notes"])
    lines.extend(f"- {item}" for item in model.epistemic_notes)
    return "\n".join(lines) + "\n"


def render_incident_review_json(review: IncidentReview | dict[str, Any]) -> str:
    """Render incident review json for toolkit workflows.

    Args:
        review: Value supplied by the caller for review.

    Returns:
        Computed result for the requested operation.

    Side effects:
        None.
    """
    model = review if isinstance(review, IncidentReview) else IncidentReview.model_validate(review)
    return json.dumps(model.model_dump(mode="json"), indent=2) + "\n"

"""Load Procmon CSV exports referencing WinINET HKCU proxy ``RegSetValue`` / ``SetValue`` writes."""

from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .attribution_model import AttributionEvidence

_INTERNET_SETTINGS = "internet settings"


def _norm_header(name: str) -> str:
    return name.strip().lower().replace("_", " ")


def load_procmon_proxy_events(
    csv_path: str,
    since_seconds: int | None = None,
) -> list[AttributionEvidence]:
    """Parse Procmon-ish CSV rows for successful registry writes on proxy WinINET values.

    Args:
        csv_path: Readable CSV path exported from Process Monitor (registry filter recommended).
        since_seconds: When set, excludes rows clearly older than *now − since_seconds* when a parseable UTC
            or time-of-day field exists; loosely enforced when timestamps are ambiguous.

    Returns:
        ``AttributionEvidence`` list with ``source`` ``procmon_csv`` (possibly empty).

    Raises:
        None — unreadable paths yield empty list plus no exception (logged by callers if needed).
    """
    path = Path(csv_path)
    if not path.is_file():
        return []

    now_ts = datetime.now(UTC).timestamp()

    hits: list[AttributionEvidence] = []
    try:
        with path.open(encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                return []
            remap = {_norm_header(h): h for h in reader.fieldnames}

            def col(*candidates: str) -> str | None:
                for c in candidates:
                    key = remap.get(_norm_header(c))
                    if key:
                        return key
                return None

            c_time = col("time of day", "time", "date time", "utc time")
            c_pid = col("pid", "process id")
            c_proc = col("process name", "process", "application")
            c_op = col("operation")
            c_path = col("path", "registry path", "name")
            c_result = col("result")
            c_detail = col("detail", "detail data")

            proxy_tail = ("proxyenable", "proxyserver", "autoconfigurl", "autodetect", "proxyoverride")

            for row in reader:
                op_cell = str(row.get(c_op or "") or "").lower()
                if "regsetvalue" not in op_cell and "setvalue" not in op_cell:
                    continue
                rp = str(row.get(c_path or "") or "").lower()
                if _INTERNET_SETTINGS not in rp:
                    continue
                if not any(x in rp for x in proxy_tail):
                    continue
                res_cell = str(row.get(c_result or "") or "").upper()
                if res_cell and "SUCCESS" not in res_cell and "SUCCESSFULL" not in res_cell:
                    continue

                time_s = str(row.get(c_time or "") or "").strip()
                observed = time_s[:80] if time_s else None
                skip_time = False
                if since_seconds is not None and time_s:
                    parsed_ts: float | None = None
                    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%m/%d/%Y %I:%M:%S %p", "%H:%M:%S.%f", "%H:%M:%S"):
                        try:
                            dt = datetime.strptime(time_s[:26], fmt)  # type: ignore[arg-type]
                            parsed_ts = dt.replace(tzinfo=UTC).timestamp()
                            break
                        except ValueError:
                            continue
                    if parsed_ts is not None and (now_ts - parsed_ts) > float(since_seconds) + 5.0:
                        skip_time = True
                if skip_time:
                    continue

                pid_cell = row.get(c_pid or "")
                pid: int | None = None
                if isinstance(pid_cell, str) and pid_cell.strip().isdigit():
                    pid = int(pid_cell.strip())
                elif isinstance(pid_cell, int):
                    pid = int(pid_cell)

                proc_n = row.get(c_proc or "") or ""

                excerpt: dict[str, Any] = {
                    "process_name": str(proc_n),
                    "pid": pid,
                    "path": str(row.get(c_path or "") or ""),
                    "operation": str(row.get(c_op or "") or ""),
                    "detail_snippet": str(row.get(c_detail or "") or "")[:1024],
                }

                proximity = (
                    float(since_seconds) if since_seconds is not None else 120.0
                )
                conf = 0.88 if proximity <= 120 else 0.62

                hits.append(
                    AttributionEvidence(
                        source="procmon_csv",
                        observed_at=observed,
                        target_key=str(row.get(c_path or "") or "")[:2048],
                        raw_excerpt=excerpt,
                        confidence_score=conf,
                        notes=[
                            "Procmon CSV row references RegSetValue on WinINET proxy path",
                            "Timestamp proximity to registry poll is heuristic when CSV lacks full date",
                        ],
                    ),
                )
    except OSError:
        return []

    if not hits:
        return [
            AttributionEvidence(
                source="procmon_csv",
                confidence_score=0.0,
                notes=["No Procmon RegSetValue row matched proxy Internet Settings filters"],
            ),
        ]
    return hits

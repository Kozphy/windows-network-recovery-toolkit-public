"""Google SRE-style reliability layer — event sourcing, RCA, MTTR, postmortems.

Correctness over convenience:
    - Single canonical domain event log
    - Deterministic projections (replayable)
    - Failure domain isolation with explicit degradation
    - Evidence-driven RCA (observation != proof)
"""

from platform_core.sre.event_store import DomainEventStore, append_domain_event
from platform_core.sre.failure_domains import FailureDomain, execute_in_domain
from platform_core.sre.incident_aggregate import IncidentAggregate
from platform_core.sre.investigation import run_investigation
from platform_core.sre.models import IncidentPhase
from platform_core.sre.mttr import compute_incident_mttr_metrics
from platform_core.sre.postmortem import generate_postmortem
from platform_core.sre.projector import Projector, rebuild_incident
from platform_core.sre.rca import build_rca_report
from platform_core.sre.timeline import reconstruct_timeline

__all__ = [
    "DomainEventStore",
    "append_domain_event",
    "FailureDomain",
    "execute_in_domain",
    "IncidentAggregate",
    "IncidentPhase",
    "run_investigation",
    "compute_incident_mttr_metrics",
    "generate_postmortem",
    "Projector",
    "rebuild_incident",
    "build_rca_report",
    "reconstruct_timeline",
]

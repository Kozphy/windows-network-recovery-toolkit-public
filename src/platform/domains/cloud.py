"""Document src.platform.domains.cloud responsibilities.

Module responsibility:
    Owns platform orchestration models, adapters, or compatibility helpers without asserting causal certainty beyond available evidence.

System placement:
    Used by CLI, API, or platform services that assemble endpoint evidence and governance outputs.

Key invariants:
    Keeps observations, hypotheses, policy decisions, remediation, and audit records separate.

Side effects:
    Importing this module has no intended runtime side effects beyond defining constants, classes, or functions.
"""

from src.platform.domains._evidence import FixtureEvidenceAdapter


class CloudAdapter(FixtureEvidenceAdapter):
    """Represent cloud adapter data used by the toolkit.

    Attributes:
        domain_name: Field or variant describing domain name evidence or state.

    Limitations:
        Represents recorded observations or configured policy data; it is not a standalone proof of causality.
    """

    domain_name = "cloud"

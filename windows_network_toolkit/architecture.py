"""Architecture module map for the Technology Risk & Control Analytics Platform.

Module responsibility:
    Provides a single ``MODULE_MAP`` constant that documents the canonical
    grouping of source paths by functional layer (collectors, classifiers,
    policy, audit, reports, CLI, LAN privacy, and router evidence).  This map is
    consumed by tooling, documentation generators, and onboarding scripts.

System placement:
    Imported by developer tooling, documentation generation scripts, and any
    component that needs a deterministic, code-indexed list of module paths.
    Not imported at runtime by the CLI or API surfaces.

Key invariants:
    ``MODULE_MAP`` is a read-only constant — do not mutate it at runtime.
    Path strings are repository-relative and should be updated when directories
    are renamed or moved.

Side effects:
    None — this module only defines a constant.
"""

from __future__ import annotations

MODULE_MAP = {
    "collectors": [
        "windows_network_toolkit/collectors/",
        "windows_network_toolkit/proxy_state.py",
        "windows_network_toolkit/proxy_owner.py",
        "windows_network_toolkit/collectors/playwright_collector.py",
    ],
    "classifiers": [
        "src/platform_core/classification/engine.py",
        "windows_network_toolkit/proxy_classification.py",
        "windows_network_toolkit/incident_classifier.py",
    ],
    "policy": [
        "src/platform_core/policy/engine.py",
        "src/platform_core/policy/outcome_normalizer.py",
        "config/policy/enterprise_default.yaml",
    ],
    "audit": [
        "src/platform_core/governance/chain_of_custody.py",
        "src/platform_core/audit/writer.py",
        "windows_network_toolkit/audit/",
    ],
    "reports": [
        "src/platform_core/evidence_report/generator.py",
        "src/platform_core/governance/audit_report.py",
        "windows_network_toolkit/analytics_pipeline.py",
    ],
    "cli": ["windows_network_toolkit/cli.py"],
    "lan_privacy": [
        "windows_network_toolkit/diagnostics/lan_privacy/",
        "windows_network_toolkit/lan_control_tests.py",
    ],
    "router_evidence": ["windows_network_toolkit/diagnostics/router_evidence/"],
}

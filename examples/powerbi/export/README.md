# Power BI Semantic Model Pack

Exported by `powerbi-export` from Technology Risk & Control Analytics Platform audit evidence.

## Tables

| File | Role |
|------|------|
| fact_incidents.csv | Incident grain — risk level, proof tier keys, execution authority |
| fact_control_tests.csv | Control test results per incident |
| fact_policy_decisions.csv | Policy gate outcomes — preview, block, human confirmation |
| fact_risks.csv | Risk register heat-map grain — probability, impact, severity |
| fact_recommendations.csv | Cloud governance recommendations (mock/sample) |
| fact_costs.csv | FinOps monthly cost facts (mock/sample) |
| dim_classification.csv | Triage labels — **is_security_accusation is always false** |
| dim_date.csv | Calendar dimension (mark as date table in Power BI) |
| dim_stakeholder.csv | Forum / audience for reporting |
| dim_proof_tier.csv | T0–T4 evidence maturity ordering (legacy compatibility) |
| dim_evidence_tier.csv | T0–T5 evidence tier dimension |
| dim_category.csv | Risk and cloud governance categories |
| dim_control.csv | CTRL-001–010 control catalog |
| dim_resource.csv | Cloud resource dimension (Azure/GCP mock) |

## Relationships

- dim_date[date_key] → fact_*[date_key]
- dim_classification[classification_key] → fact_incidents[classification_key]
- dim_proof_tier[proof_tier_key] → fact_incidents[proof_tier_key]
- dim_stakeholder[stakeholder_key] → fact_incidents[stakeholder_key]
- fact_incidents[incident_id] → fact_control_tests[incident_id]
- fact_incidents[incident_id] → fact_policy_decisions[incident_id]
- dim_category[category_key] → fact_risks[category_key]
- dim_evidence_tier[evidence_tier_key] → fact_risks[evidence_tier_key]
- dim_control[control_key] → fact_risks[control_key]
- dim_resource[resource_key] → fact_recommendations[resource_key]
- dim_resource[resource_key] → fact_costs[resource_key]
- dim_category[category_key] → fact_recommendations[category_key]
- dim_category[category_key] → fact_costs[category_key]

## Governance

- Classification is **not accusation** — not malware detection or EDR
- Remediation remains **preview-only** unless human_confirmed with audit evidence
- CSV snapshot — not append-only JSONL custody

See `examples/powerbi/report_blueprint.md` and `examples/powerbi/dax/measures.md`.

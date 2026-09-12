# Power Query Guidance — Importing Star Schema CSVs

## Step 1: Get data

1. Open **Power BI Desktop**
2. **Home → Get data → Text/CSV**
3. Select all files from `examples/powerbi/export/`:
   - `fact_incidents.csv`
   - `fact_control_tests.csv`
   - `fact_policy_decisions.csv`
   - `dim_classification.csv`
   - `dim_date.csv`
   - `dim_stakeholder.csv`
   - `dim_proof_tier.csv`

## Step 2: Set data types

| Table | Column | Type |
|-------|--------|------|
| All facts | `date_key` | Whole number |
| fact_incidents | `confidence_score` | Decimal |
| fact_incidents | `has_limitations` | True/False |
| fact_policy_decisions | `human_confirmation_required`, `confirmed` | True/False |
| fact_control_tests | `evidence_available` | True/False |
| dim_date | `date` | Date |
| dim_classification | `is_security_accusation` | True/False |

Use **Transform data** → detect types, then verify booleans are not text `"True"`/`"False"` strings (change if needed).

## Step 3: Mark date table

1. Select `dim_date`
2. **Table tools → Mark as date table**
3. Use column: `date`

## Step 4: Create relationships

In **Model** view, create:

```text
dim_date[date_key]          → fact_incidents[date_key]
dim_date[date_key]          → fact_control_tests[date_key]
dim_date[date_key]          → fact_policy_decisions[date_key]
dim_classification[classification_key] → fact_incidents[classification_key]
dim_proof_tier[proof_tier_key]         → fact_incidents[proof_tier_key]
dim_stakeholder[stakeholder_key]         → fact_incidents[stakeholder_key]
fact_incidents[incident_id] → fact_control_tests[incident_id]
fact_incidents[incident_id] → fact_policy_decisions[incident_id]
```

**Cardinality:** One-to-many from dimensions to facts; one-to-many from `fact_incidents` to child facts.

## Step 5: Modeling best practices

- **Avoid many-to-many** — use dimension keys, not text labels, on fact tables
- **Keep facts numeric and event-based** — measures aggregate on facts
- **Keep descriptive text in dimensions** — classification descriptions, proof tier labels
- **Hide keys** on fact tables if desired (classification_key, proof_tier_key) after relationships exist
- **Do not import README.md** as a table

## Step 6: Refresh

For portfolio work, use **Close & Apply** after import. For production, schedule refresh from a secure data lake that runs:

```powershell
python -m windows_network_toolkit powerbi-export --audit-dir <audit-path> --out-dir <staging>
```

## Governance reminder

CSV export is a snapshot. Append-only JSONL remains the audit source of truth.

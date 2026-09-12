# Row-Level Security Design (Portfolio)

**Scope:** Design document only — no authentication implementation.

This RLS model aligns with the platform governance principle: **classification is not accusation**.

---

## Role: IT Support

**Purpose:** Diagnose endpoint reliability and view remediation previews.

| Table | Filter |
|-------|--------|
| fact_incidents | All rows |
| fact_policy_decisions | All rows |
| fact_control_tests | `control_domain = "Endpoint Reliability"` |
| dim_classification | All rows |

**Hidden:** Aggregated-only fields for Risk Committee KPIs (optional).

**Cannot:** See raw `blocked_reason` detail for security-only blocks (optional column security).

---

## Role: Security

**Purpose:** Review classifications and proof tiers without malware accusation semantics.

| Table | Filter |
|-------|--------|
| fact_incidents | All rows |
| dim_proof_tier | All rows |
| dim_classification | `is_security_accusation = FALSE` (all rows in this model) |

**DAX filter example (illustrative):**

```dax
dim_classification[is_security_accusation] = FALSE ()
```

**Narrative rule:** Dashboards must not label visuals "Malware" or "Compromise confirmed."

---

## Role: Audit

**Purpose:** Audit trail, limitations, governance envelope fields.

| Table | Filter |
|-------|--------|
| fact_incidents | All rows |
| fact_policy_decisions | All rows |
| fact_control_tests | All rows |

**Emphasis visuals:** `has_limitations`, `human_confirmation_required`, `blocked_reason`, `audit_id`

**Cannot:** Modify dataset — read-only workspace role in production.

---

## Role: Risk Committee

**Purpose:** Aggregated KPIs only — no endpoint-level drilldown.

| Table | Filter |
|-------|--------|
| fact_incidents | **None at row level** — use aggregated visuals only |

**Implementation pattern:**

- Provide a separate **aggregated** table or use measures without exposing `incident_id` in visuals
- Hide `fact_incidents` detail columns; show only cards and trends
- Optional DAX: block drillthrough via visual-level filters

**Measures exposed:** Total Incidents, High Risk Incidents, Control Failure Rate, Preview Only Decisions

---

## Column-level security (optional)

| Column | IT Support | Security | Audit | Risk Committee |
|--------|------------|----------|-------|----------------|
| incident_id | Visible | Visible | Visible | Hidden |
| audit_id | Visible | Hidden | Visible | Hidden |
| confidence_score | Visible | Visible | Visible | Aggregated only |

---

## Workspace assumptions

- **Dev / Test / Prod** workspaces with deployment pipeline
- **Build** permission for analysts; **Read** for committee consumers
- **Gateway** not required for CSV import mode
- **Sensitivity label:** Internal — not public

---

## Limitations

- RLS does not replace policy gates in the Python platform
- Exported CSV breaks append-only audit guarantees — link to JSONL for formal audit
- No regulatory sign-off implied by any role

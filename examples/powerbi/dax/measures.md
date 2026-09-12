# DAX Measure Examples — Technology Risk Star Schema

**Assumptions**

- Fact table: `fact_incidents`
- Policy fact: `fact_policy_decisions`
- Control fact: `fact_control_tests`
- Date table: `dim_date` (marked as date table)
- Relationships are active and single-direction from dimensions to facts

---

## Incident volume

```dax
Total Incidents =
COUNTROWS ( fact_incidents )
```

```dax
High Risk Incidents =
CALCULATE (
    COUNTROWS ( fact_incidents ),
    fact_incidents[risk_level] IN { "HIGH", "CRITICAL" }
)
```

```dax
Security Accusation Count =
CALCULATE (
    COUNTROWS ( fact_incidents ),
    RELATED ( dim_classification[is_security_accusation] ) = TRUE ()
)
```

> **Portfolio note:** This measure should normally return **zero**. Classification is not accusation in this platform.

---

## Control effectiveness

```dax
Control Tests Failed =
CALCULATE (
    COUNTROWS ( fact_control_tests ),
    fact_control_tests[result] = "FAIL"
)
```

```dax
Control Failure Rate =
DIVIDE (
    CALCULATE (
        COUNTROWS ( fact_control_tests ),
        fact_control_tests[result] IN { "FAIL", "PARTIAL" }
    ),
    COUNTROWS ( fact_control_tests ),
    0
)
```

---

## Policy gates

```dax
Preview Only Decisions =
CALCULATE (
    COUNTROWS ( fact_policy_decisions ),
    fact_policy_decisions[policy_action] = "PREVIEW_ONLY"
)
```

```dax
Confirmed Actions =
CALCULATE (
    COUNTROWS ( fact_policy_decisions ),
    fact_policy_decisions[confirmed] = TRUE ()
)
```

---

## Evidence quality

```dax
Incidents with Limitations =
CALCULATE (
    COUNTROWS ( fact_incidents ),
    fact_incidents[has_limitations] = TRUE ()
)
```

```dax
Average Confidence Score =
AVERAGE ( fact_incidents[confidence_score] )
```

```dax
T0 to T4 Proof Coverage =
VAR WithProof =
    CALCULATE (
        COUNTROWS ( fact_incidents ),
        fact_incidents[proof_tier_key] >= 1
    )
RETURN
    DIVIDE ( WithProof, [Total Incidents], 0 )
```

---

## Time intelligence

```dax
Monthly Incident Trend =
CALCULATE (
    [Total Incidents],
    DATESMTD ( dim_date[date] )
)
```

For a simple line chart by month, use `dim_date[month_name]` on the axis and `[Total Incidents]` as the value.

---

## Formatting tips

| Measure | Suggested format |
|---------|------------------|
| Control Failure Rate, T0 to T4 Proof Coverage | Percentage |
| Average Confidence Score | Decimal number (2 places) |
| Count measures | Whole number |

Add a report footer: *Measures support technology risk triage — not malware verdicts or regulatory attestation.*

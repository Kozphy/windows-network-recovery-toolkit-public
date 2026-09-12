-- Technology Risk persistence (mounted as 03_trisk_schema.sql in Docker)
-- Portfolio prototype — complements platform_core/db/schema.sql

CREATE TABLE IF NOT EXISTS trisk_endpoints (
    id SERIAL PRIMARY KEY,
    endpoint_id VARCHAR(128) NOT NULL UNIQUE,
    hostname VARCHAR(256),
    tenant_id VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trisk_evidence_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    source_event_id VARCHAR(128),
    content_hash VARCHAR(64) NOT NULL,
    endpoint_id VARCHAR(128) NOT NULL,
    evidence_type VARCHAR(64) NOT NULL,
    evidence_tier VARCHAR(64) NOT NULL DEFAULT 'T1_STATE_EVIDENCE',
    raw_snapshot JSONB NOT NULL DEFAULT '{}',
    normalized_fields JSONB NOT NULL DEFAULT '{}',
    limitations JSONB NOT NULL DEFAULT '[]',
    classification_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    job_id VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (endpoint_id, source_event_id)
);

CREATE INDEX IF NOT EXISTS idx_trisk_evidence_content_hash ON trisk_evidence_events (content_hash);
CREATE INDEX IF NOT EXISTS idx_trisk_evidence_endpoint ON trisk_evidence_events (endpoint_id);

CREATE TABLE IF NOT EXISTS trisk_incidents (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL UNIQUE,
    evidence_event_id VARCHAR(64) NOT NULL REFERENCES trisk_evidence_events(event_id),
    endpoint_id VARCHAR(128) NOT NULL,
    primary_classification VARCHAR(64) NOT NULL,
    secondary_signals JSONB NOT NULL DEFAULT '[]',
    proof_tier VARCHAR(64) NOT NULL DEFAULT 'T1_STATE_EVIDENCE',
    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    limitations JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trisk_control_tests (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES trisk_incidents(incident_id),
    control_id VARCHAR(32) NOT NULL,
    test_result VARCHAR(32) NOT NULL,
    evidence JSONB NOT NULL DEFAULT '[]',
    limitations JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trisk_policy_decisions (
    id SERIAL PRIMARY KEY,
    incident_id VARCHAR(64) NOT NULL REFERENCES trisk_incidents(incident_id),
    action VARCHAR(64) NOT NULL,
    outcome VARCHAR(64) NOT NULL,
    dry_run BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trisk_risk_decisions (
    id SERIAL PRIMARY KEY,
    decision_id VARCHAR(64) NOT NULL UNIQUE,
    incident_id VARCHAR(64) NOT NULL REFERENCES trisk_incidents(incident_id),
    actor VARCHAR(128) NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    policy_decision_id VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trisk_human_reviews (
    id SERIAL PRIMARY KEY,
    review_id VARCHAR(64) NOT NULL UNIQUE,
    incident_id VARCHAR(64) NOT NULL REFERENCES trisk_incidents(incident_id),
    evidence_id VARCHAR(64) NOT NULL,
    classification VARCHAR(64) NOT NULL,
    policy_decision_id VARCHAR(64) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_REVIEW',
    actor VARCHAR(128),
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trisk_audit_chain (
    id SERIAL PRIMARY KEY,
    row_index INTEGER NOT NULL,
    prev_hash VARCHAR(128) NOT NULL,
    row_hash VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trisk_audit_row_index ON trisk_audit_chain (row_index);

CREATE TABLE IF NOT EXISTS trisk_domain_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    event_type VARCHAR(64) NOT NULL,
    aggregate_id VARCHAR(128) NOT NULL,
    aggregate_type VARCHAR(32) NOT NULL DEFAULT 'evidence',
    sequence INTEGER NOT NULL,
    actor VARCHAR(128) NOT NULL DEFAULT 'system',
    correlation_id VARCHAR(128) NOT NULL DEFAULT '',
    payload JSONB NOT NULL DEFAULT '{}',
    limitations JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trisk_domain_events_aggregate ON trisk_domain_events (aggregate_id, sequence);

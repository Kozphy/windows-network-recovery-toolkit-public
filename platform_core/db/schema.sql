-- Endpoint Reliability Platform — PostgreSQL append-only schema
-- Apply: psql $DATABASE_URL -f platform_core/db/schema.sql

CREATE TABLE IF NOT EXISTS platform_events (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    timestamp_utc TIMESTAMPTZ NOT NULL,
    endpoint_id VARCHAR(128) NOT NULL,
    source_kind VARCHAR(32) NOT NULL,
    signal_name VARCHAR(256) NOT NULL,
    evidence_tier VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_platform_events_endpoint_ts
    ON platform_events (endpoint_id, timestamp_utc DESC);

CREATE TABLE IF NOT EXISTS platform_state_transitions (
    id BIGSERIAL PRIMARY KEY,
    transition_id VARCHAR(64) NOT NULL UNIQUE,
    timestamp_utc TIMESTAMPTZ NOT NULL,
    endpoint_id VARCHAR(128) NOT NULL,
    from_state VARCHAR(64) NOT NULL,
    to_state VARCHAR(64) NOT NULL,
    rule_id VARCHAR(128) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    triggering_event_ids JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS platform_decisions (
    id BIGSERIAL PRIMARY KEY,
    decision_id VARCHAR(64) NOT NULL UNIQUE,
    run_id VARCHAR(64) NOT NULL,
    timestamp_utc TIMESTAMPTZ NOT NULL,
    endpoint_id VARCHAR(128) NOT NULL,
    state_path JSONB NOT NULL DEFAULT '[]',
    accepted_hypothesis TEXT,
    policy_outcome VARCHAR(16) NOT NULL,
    policy_reason_codes JSONB NOT NULL DEFAULT '[]',
    evidence_graph_summary JSONB NOT NULL DEFAULT '{}',
    hypothesis_ranking JSONB NOT NULL DEFAULT '[]',
    event_ids JSONB NOT NULL DEFAULT '[]',
    limitations JSONB NOT NULL DEFAULT '[]',
    audit_signature VARCHAR(128),
    schema_version VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_platform_decisions_run ON platform_decisions (run_id);
CREATE INDEX IF NOT EXISTS idx_platform_decisions_endpoint_ts
    ON platform_decisions (endpoint_id, timestamp_utc DESC);

-- SRE canonical domain event log (event sourcing)
CREATE TABLE IF NOT EXISTS sre_domain_events (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    sequence INT NOT NULL,
    aggregate_id VARCHAR(128) NOT NULL,
    aggregate_type VARCHAR(32) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    timestamp_utc TIMESTAMPTZ NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    causation_id VARCHAR(64),
    failure_domain VARCHAR(32),
    actor VARCHAR(128) NOT NULL DEFAULT 'system',
    payload JSONB NOT NULL DEFAULT '{}',
    schema_version VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (aggregate_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_sre_events_correlation ON sre_domain_events (correlation_id, timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_sre_events_aggregate ON sre_domain_events (aggregate_id, sequence);

-- Immutable audit: no UPDATE/DELETE triggers (application-enforced append-only)

-- Decision Intelligence API — PostgreSQL schema (append-oriented)
-- Apply after platform_core/db/schema.sql when using the full stack.

CREATE TABLE IF NOT EXISTS di_events (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(64) NOT NULL UNIQUE,
    domain VARCHAR(64) NOT NULL DEFAULT 'generic',
    title TEXT NOT NULL,
    category VARCHAR(64) NOT NULL DEFAULT '',
    timestamp_utc TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_di_events_domain_ts ON di_events (domain, timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS idx_di_events_category ON di_events (category);

CREATE TABLE IF NOT EXISTS di_evidence (
    id BIGSERIAL PRIMARY KEY,
    evidence_id VARCHAR(64) NOT NULL UNIQUE,
    event_id VARCHAR(64) NOT NULL DEFAULT '',
    decision_id VARCHAR(64) NOT NULL DEFAULT '',
    label TEXT NOT NULL,
    kind VARCHAR(32) NOT NULL DEFAULT 'observation',
    weight DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    supports_decision BOOLEAN,
    detail TEXT NOT NULL DEFAULT '',
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_di_evidence_event ON di_evidence (event_id);
CREATE INDEX IF NOT EXISTS idx_di_evidence_decision ON di_evidence (decision_id);
CREATE INDEX IF NOT EXISTS idx_di_evidence_kind ON di_evidence (kind);

CREATE TABLE IF NOT EXISTS di_decisions (
    id BIGSERIAL PRIMARY KEY,
    decision_id VARCHAR(64) NOT NULL UNIQUE,
    domain VARCHAR(64) NOT NULL,
    title TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL,
    policy_status VARCHAR(32) NOT NULL DEFAULT 'PREVIEW',
    payload JSONB NOT NULL DEFAULT '{}',
    content_digest VARCHAR(128) NOT NULL DEFAULT '',
    timestamp_utc TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_di_decisions_domain_ts ON di_decisions (domain, timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS idx_di_decisions_policy ON di_decisions (policy_status);

CREATE TABLE IF NOT EXISTS di_outcomes (
    id BIGSERIAL PRIMARY KEY,
    outcome_id VARCHAR(64) NOT NULL UNIQUE,
    decision_id VARCHAR(64) NOT NULL,
    outcome TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    predicted_success BOOLEAN NOT NULL DEFAULT TRUE,
    cost DOUBLE PRECISION NOT NULL DEFAULT 0,
    time_to_resolution DOUBLE PRECISION NOT NULL DEFAULT 0,
    notes TEXT NOT NULL DEFAULT '',
    recorded_at_utc TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_di_outcomes_decision ON di_outcomes (decision_id);
CREATE INDEX IF NOT EXISTS idx_di_outcomes_success ON di_outcomes (success);

-- Enterprise Decision Intelligence Platform schema (04_enterprise_decision_platform.sql)
-- Complements trisk_* tables in schema.sql

CREATE TABLE IF NOT EXISTS trisk_tenants (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL UNIQUE,
    display_name VARCHAR(256) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trisk_observations (
    id SERIAL PRIMARY KEY,
    observation_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES trisk_tenants(tenant_id),
    endpoint_id VARCHAR(128) NOT NULL,
    signal_type VARCHAR(64) NOT NULL,
    raw_observation JSONB NOT NULL DEFAULT '{}',
    limitations JSONB NOT NULL DEFAULT '[]',
    correlation_id VARCHAR(128) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trisk_observations_tenant ON trisk_observations (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS trisk_hypotheses (
    id SERIAL PRIMARY KEY,
    hypothesis_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES trisk_tenants(tenant_id),
    observation_id VARCHAR(64) REFERENCES trisk_observations(observation_id),
    evidence_event_id VARCHAR(64),
    label VARCHAR(128) NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    confidence_ordinal VARCHAR(16) NOT NULL DEFAULT 'medium',
    status VARCHAR(32) NOT NULL DEFAULT 'proposed',
    limitations JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trisk_hypotheses_tenant ON trisk_hypotheses (tenant_id, status);

CREATE TABLE IF NOT EXISTS trisk_platform_decisions (
    id SERIAL PRIMARY KEY,
    decision_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES trisk_tenants(tenant_id),
    incident_id VARCHAR(64),
    hypothesis_id VARCHAR(64) REFERENCES trisk_hypotheses(hypothesis_id),
    evidence_event_id VARCHAR(64) NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    confidence_label VARCHAR(16) NOT NULL DEFAULT 'medium',
    policy_outcome VARCHAR(64) NOT NULL DEFAULT 'PREVIEW_ONLY',
    recommended_action VARCHAR(64) NOT NULL DEFAULT 'OBSERVE',
    execution_authority VARCHAR(64) NOT NULL DEFAULT 'preview_only',
    human_approval_required BOOLEAN NOT NULL DEFAULT TRUE,
    human_approval_status VARCHAR(32) NOT NULL DEFAULT 'pending',
    actor VARCHAR(128) NOT NULL DEFAULT 'system',
    rationale TEXT NOT NULL DEFAULT '',
    limitations JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trisk_platform_decisions_tenant ON trisk_platform_decisions (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS trisk_policy_packs (
    id SERIAL PRIMARY KEY,
    pack_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES trisk_tenants(tenant_id),
    version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    yaml_content TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_trisk_policy_packs_active
    ON trisk_policy_packs (tenant_id) WHERE active = TRUE;

CREATE TABLE IF NOT EXISTS trisk_audit_logs (
    id SERIAL PRIMARY KEY,
    log_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(64) NOT NULL REFERENCES trisk_tenants(tenant_id),
    correlation_id VARCHAR(128) NOT NULL DEFAULT '',
    event_type VARCHAR(64) NOT NULL,
    actor VARCHAR(128) NOT NULL DEFAULT 'system',
    resource_type VARCHAR(32) NOT NULL DEFAULT 'decision',
    resource_id VARCHAR(128) NOT NULL DEFAULT '',
    payload JSONB NOT NULL DEFAULT '{}',
    prev_hash VARCHAR(128) NOT NULL DEFAULT 'genesis',
    row_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trisk_audit_logs_tenant ON trisk_audit_logs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_trisk_audit_logs_correlation ON trisk_audit_logs (correlation_id);

-- Tenant scoping on existing evidence (nullable for backward compatibility)
ALTER TABLE trisk_evidence_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);
ALTER TABLE trisk_incidents ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_trisk_evidence_tenant ON trisk_evidence_events (tenant_id);
CREATE INDEX IF NOT EXISTS idx_trisk_incidents_tenant ON trisk_incidents (tenant_id);

INSERT INTO trisk_tenants (tenant_id, display_name, status)
VALUES ('default', 'Default Tenant', 'active')
ON CONFLICT (tenant_id) DO NOTHING;

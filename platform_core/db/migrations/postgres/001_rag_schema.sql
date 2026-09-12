-- RAG schema — PostgreSQL + pgvector (production)
-- Requires: CREATE EXTENSION vector;

CREATE TABLE IF NOT EXISTS rag_incidents (
    incident_id       TEXT PRIMARY KEY,
    investigation_id  TEXT,
    endpoint_id       TEXT NOT NULL DEFAULT 'local',
    primary_domain    TEXT NOT NULL,
    primary_classification TEXT NOT NULL DEFAULT '',
    severity          TEXT NOT NULL DEFAULT 'medium',
    confidence_ordinal DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    status            TEXT NOT NULL DEFAULT 'open',
    source_type       TEXT NOT NULL DEFAULT 'live',
    source_ref        TEXT NOT NULL DEFAULT '',
    payload_json      JSONB NOT NULL DEFAULT '{}',
    content_digest    TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rag_incidents_domain_cls
    ON rag_incidents (primary_domain, primary_classification);

CREATE TABLE IF NOT EXISTS rag_documents (
    document_id       TEXT PRIMARY KEY,
    incident_id       TEXT NOT NULL REFERENCES rag_incidents(incident_id) ON DELETE CASCADE,
    doc_type          TEXT NOT NULL,
    title             TEXT NOT NULL DEFAULT '',
    failure_domain    TEXT NOT NULL,
    evidence_tier     TEXT NOT NULL DEFAULT 'OBSERVED_ONLY',
    language          TEXT NOT NULL DEFAULT 'en',
    payload_json      JSONB NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rag_chunks (
    chunk_id          TEXT PRIMARY KEY,
    document_id       TEXT NOT NULL REFERENCES rag_documents(document_id) ON DELETE CASCADE,
    incident_id       TEXT NOT NULL REFERENCES rag_incidents(incident_id) ON DELETE CASCADE,
    chunk_index       INTEGER NOT NULL DEFAULT 0,
    chunk_text        TEXT NOT NULL,
    chunk_text_hash   TEXT NOT NULL,
    failure_domain    TEXT NOT NULL,
    signal_tags       JSONB NOT NULL DEFAULT '[]',
    classification_tags JSONB NOT NULL DEFAULT '[]',
    evidence_tier     TEXT NOT NULL DEFAULT 'OBSERVED_ONLY',
    token_count       INTEGER NOT NULL DEFAULT 0,
    metadata_json     JSONB NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rag_chunks_domain ON rag_chunks (failure_domain);
CREATE INDEX IF NOT EXISTS idx_rag_chunks_meta_gin ON rag_chunks USING gin (metadata_json);

CREATE TABLE IF NOT EXISTS rag_chunk_evidence (
    chunk_id          TEXT NOT NULL REFERENCES rag_chunks(chunk_id) ON DELETE CASCADE,
    evidence_id       TEXT NOT NULL,
    signal            TEXT NOT NULL DEFAULT '',
    tier              TEXT NOT NULL DEFAULT 'OBSERVED_ONLY',
    observed_value    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (chunk_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS rag_embeddings (
    chunk_id          TEXT PRIMARY KEY REFERENCES rag_chunks(chunk_id) ON DELETE CASCADE,
    model_id          TEXT NOT NULL,
    dimensions        INTEGER NOT NULL,
    embedding         vector(384) NOT NULL,
    norm              DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rag_embeddings_hnsw
    ON rag_embeddings USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE TABLE IF NOT EXISTS rag_cases (
    case_id           TEXT PRIMARY KEY,
    title             TEXT NOT NULL,
    primary_domain    TEXT NOT NULL,
    primary_classification TEXT NOT NULL,
    fixture_path      TEXT NOT NULL,
    timeline_path     TEXT NOT NULL DEFAULT '',
    tags_json         JSONB NOT NULL DEFAULT '[]',
    principles_validated BOOLEAN NOT NULL DEFAULT FALSE,
    incident_id       TEXT REFERENCES rag_incidents(incident_id),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rag_retrieval_sessions (
    session_id        TEXT PRIMARY KEY,
    investigation_id  TEXT,
    query_text        TEXT NOT NULL,
    query_domain      TEXT NOT NULL DEFAULT '',
    query_classification TEXT NOT NULL DEFAULT '',
    query_payload_json JSONB NOT NULL DEFAULT '{}',
    model_id          TEXT NOT NULL,
    backend           TEXT NOT NULL DEFAULT 'postgresql',
    hit_count         INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rag_retrieval_hits (
    hit_id            TEXT PRIMARY KEY,
    session_id        TEXT NOT NULL REFERENCES rag_retrieval_sessions(session_id) ON DELETE CASCADE,
    chunk_id          TEXT NOT NULL,
    incident_id       TEXT NOT NULL,
    case_id           TEXT,
    vector_score      DOUBLE PRECISION NOT NULL,
    feature_score     DOUBLE PRECISION NOT NULL,
    hybrid_score      DOUBLE PRECISION NOT NULL,
    rank              INTEGER NOT NULL,
    explain_json      JSONB NOT NULL DEFAULT '{}',
    evidence_ids_json JSONB NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_rag_hits_session ON rag_retrieval_hits (session_id, rank);

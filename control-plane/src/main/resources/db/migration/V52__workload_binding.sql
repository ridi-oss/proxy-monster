CREATE TABLE workload_binding (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    issuer      TEXT NOT NULL,
    subject     TEXT NOT NULL,
    conditions  JSONB NOT NULL DEFAULT '{}'::jsonb,
    principal   TEXT NOT NULL,
    purposes    TEXT[] NOT NULL,
    mcp_scopes  TEXT[] NOT NULL DEFAULT '{}',
    ttl_seconds INTEGER NOT NULL DEFAULT 900,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ,
    CONSTRAINT workload_binding_name_ck CHECK (name ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    CONSTRAINT workload_binding_principal_ck CHECK (principal ~ '^svc:[a-z0-9][a-z0-9._-]{0,62}$'),
    CONSTRAINT workload_binding_subject_ck CHECK (length(subject) BETWEEN 1 AND 1000),
    CONSTRAINT workload_binding_conditions_ck CHECK (jsonb_typeof(conditions) = 'object'),
    CONSTRAINT workload_binding_purposes_ck CHECK (cardinality(purposes) >= 1 AND purposes <@ ARRAY['wire', 'mcp']),
    CONSTRAINT workload_binding_mcp_scopes_ck CHECK ('mcp' = ANY(purposes) OR cardinality(mcp_scopes) = 0),
    CONSTRAINT workload_binding_ttl_ck CHECK (ttl_seconds BETWEEN 60 AND 3600)
);
CREATE UNIQUE INDEX workload_binding_name_idx ON workload_binding (name) WHERE deleted_at IS NULL;
CREATE INDEX workload_binding_issuer_idx ON workload_binding (issuer) WHERE deleted_at IS NULL;

ALTER TABLE proxy_token ADD COLUMN workload_binding_id BIGINT REFERENCES workload_binding(id);
CREATE INDEX proxy_token_workload_binding_idx ON proxy_token (workload_binding_id) WHERE workload_binding_id IS NOT NULL;

ALTER TABLE proxy_token DROP CONSTRAINT proxy_token_workload_claims_ck;
ALTER TABLE proxy_token ADD CONSTRAINT proxy_token_workload_claims_ck CHECK ((kind IN ('WORKLOAD', 'SERVICE')) = (claims IS NOT NULL));
ALTER TABLE proxy_token ADD CONSTRAINT proxy_token_service_binding_ck CHECK (kind <> 'SERVICE' OR workload_binding_id IS NOT NULL);

CREATE TABLE workload_token_use (
    issuer     TEXT NOT NULL,
    jti        TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (issuer, jti)
);
CREATE INDEX workload_token_use_expiry_idx ON workload_token_use (expires_at);

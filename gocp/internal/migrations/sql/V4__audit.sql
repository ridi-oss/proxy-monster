-- The audit trail and its tamper-evident hash chain.
--
-- One row per audited event: a per-statement decision (`kind = 'decision'`) or a result event that
-- refers back to its decision through `decision_id`. Every set-valued column is a JSONB array so an
-- independent verifier can reproduce the exact hash preimage bytes from storage -- a comma-joined
-- string would round-trip lossily for a value containing a comma and falsely read as tampered.
--
-- `id` carries NO sequence default. AuditStore assigns it under the `audit_chain_head` row lock, so
-- the id order and the chain order are the same order by construction; a sequence could hand out an
-- id out of chain sequence and break verification.

CREATE TABLE audit_event (
    id             BIGINT PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind           TEXT NOT NULL DEFAULT 'decision',
    principal      TEXT NOT NULL,
    roles          JSONB NOT NULL DEFAULT '[]'::jsonb,
    datasource     TEXT NOT NULL,
    client_addr    TEXT,
    statement      TEXT NOT NULL,
    decision       TEXT NOT NULL,
    failed_stage   TEXT,
    masked_columns JSONB NOT NULL DEFAULT '[]',
    pii_touched    JSONB NOT NULL DEFAULT '[]',
    latency_ms     BIGINT NOT NULL DEFAULT 0,
    detail         TEXT,
    -- The effective namespace the decision resolved under (PG search_path / the MySQL current
    -- database), so a decision is reproducible against the names it actually bound.
    effective_namespace JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- The surface the decision came from (wire | editor | workflow-executor | workflow-viewer) and
    -- the derived context.tags the request earned.
    channel        TEXT,
    context_tags   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- Management-action attributes, for an event that is an admin mutation rather than a statement.
    action         TEXT,
    resource       TEXT,
    outcome        TEXT,
    rows_returned  BIGINT,
    bytes_returned BIGINT,
    -- A result event points at the decision it belongs to.
    decision_id    BIGINT REFERENCES audit_event(id),
    -- Each chained row stamps the canonical-format version that produced its hash, so a verifier
    -- picks the matching field set per row and a later release can add fields under a bumped version
    -- without invalidating earlier segments.
    chain_version  INT,
    prev_hash      BYTEA,
    row_hash       BYTEA,
    CONSTRAINT audit_event_roles_array CHECK (jsonb_typeof(roles) = 'array'),
    CONSTRAINT audit_event_effective_namespace_array CHECK (jsonb_typeof(effective_namespace) = 'array'),
    CONSTRAINT audit_event_context_tags_array CHECK (jsonb_typeof(context_tags) = 'array')
);
CREATE INDEX idx_audit_event_ts ON audit_event (ts DESC);

-- The single-row chain head: the last chained id and the hash covering it. AuditStore takes
-- `FOR UPDATE` on this row to serialize appends, so two concurrent writers cannot fork the chain.
CREATE TABLE audit_chain_head (
    id        INT PRIMARY KEY CHECK (id = 1),
    last_id   BIGINT NOT NULL,
    head_hash BYTEA NOT NULL
);

-- The genesis head: SHA-256 of the ASCII bytes for "pm-audit-genesis".
INSERT INTO audit_chain_head (id, last_id, head_hash)
VALUES (1, 0, decode('88d4f4719f26cf7f32839ac30b1d6a94edf3f9133fb75667d1415fff81bbcd08', 'hex'));

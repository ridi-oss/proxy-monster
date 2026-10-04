-- Tasks: access requests, the grants they mint, and stored task results.
--
-- One table carries both request kinds, discriminated by `kind`:
--
--   ROLE   time-boxed elevation. An approval mints an `access_grant`, which simply adds a role to the
--          principal's effective roles for its window -- so the ordinary per-statement decision
--          applies and there is no separate elevation path in the engine.
--   QUERY  "run this statement under role R, once". The statement lives on the `query_result` row,
--          the ceiling role set in `execute_as`, and execution authorizes with exactly {R}.
--
-- The two CHECKs keep the discriminated shape honest at the database boundary: which columns a kind
-- requires, and which status values it may hold.

CREATE TABLE access_request (
    id                     BIGSERIAL PRIMARY KEY,
    kind                   TEXT NOT NULL DEFAULT 'ROLE',      -- ROLE | QUERY
    principal              TEXT NOT NULL,                     -- the requester
    -- The role being requested (ROLE) or the role the statement runs under (QUERY).
    role_id                BIGINT REFERENCES app_role(id),
    -- The target datasource. Consumed at approval time: the task.approve Cedar check reads its tags.
    datasource_id          BIGINT REFERENCES datasource(id),
    title                  TEXT,
    reason                 TEXT,
    -- The window the requester asked for; the ROLE path reads it as the approver's window ceiling.
    requested_duration_sec BIGINT NOT NULL DEFAULT 3600,
    status                 TEXT NOT NULL DEFAULT 'PENDING',
    -- Which surface opened the task.
    creator_kind           TEXT CHECK (creator_kind IN ('WIRE', 'EDITOR', 'WORKFLOW')),
    -- For a task raised from a denial: the decision that was denied, and the reason it carried.
    source_decision_id     BIGINT REFERENCES audit_event(id) ON DELETE SET NULL,
    deny_reason            TEXT,
    evaluated_decision     TEXT,
    decided_by             TEXT,
    decided_at             TIMESTAMPTZ,
    approved_at            TIMESTAMPTZ,
    rejection_reason       TEXT,
    -- The role set execution assumes. The viewer of a saved result contributes identity and live HTTP
    -- context only, never ambient roles, so this is the ceiling for both execution and later views.
    execute_as             JSONB,
    executing_at           TIMESTAMPTZ,
    -- The execute-once claim, taken atomically by a single-statement compare-and-set
    -- (`UPDATE ... SET executed_at = now() WHERE id = ? AND executed_at IS NULL`) BEFORE the proxy is
    -- dialed, so two concurrent /execute calls yield exactly one real run on the target. Released back
    -- to NULL only on the outcomes that definitely did not execute (a DENY under R, no proxy
    -- attached); left burned on an ambiguous one (proxy timeout, target error), since the target may
    -- already have run the statement.
    executed_at            TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT access_request_kind_shape CHECK (
        (kind = 'ROLE'  AND role_id IS NOT NULL)
     OR (kind = 'QUERY' AND datasource_id IS NOT NULL)
    ),
    CONSTRAINT access_request_status_shape CHECK (
        (kind = 'ROLE'  AND status IN ('PENDING', 'APPROVED', 'REJECTED'))
     OR (kind = 'QUERY' AND status IN ('DRAFT', 'PENDING', 'APPROVED', 'REJECTED', 'EXECUTING',
                                       'EXECUTED', 'FAILED', 'CANCELLED', 'DELETED'))
    )
);
CREATE INDEX idx_access_request_kind_status ON access_request (kind, status, created_at DESC);

-- At most one pending QUERY task per source decision, enforced at the database boundary so two
-- concurrent from-denied submissions cannot both pass the application's pre-check.
CREATE UNIQUE INDEX uq_access_request_pending_query_source_decision
    ON access_request (source_decision_id)
    WHERE kind = 'QUERY' AND status = 'PENDING' AND source_decision_id IS NOT NULL;

-- A granted role, live until it expires or is revoked. The grant widens the role globally for its
-- window: RoleResolver.resolve reads only principal + role + window.
CREATE TABLE access_grant (
    id         BIGSERIAL PRIMARY KEY,
    request_id BIGINT REFERENCES access_request(id) ON DELETE CASCADE,
    principal  TEXT NOT NULL,
    role_id    BIGINT NOT NULL REFERENCES app_role(id),
    granted_by TEXT,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_access_grant_principal ON access_grant (principal) WHERE revoked_at IS NULL;

-- A task's stored result. This is the one path where the control plane persists rows from a target, so
-- they are encrypted at rest (AES-256-GCM, PM_RESULT_KEY) with short retention. The saved lineage plus
-- `access_request.execute_as` bound the result at view time: a viewer re-authorizes with exactly {R},
-- so a saved result re-masks rather than leaking a raw side channel.
CREATE TABLE query_result (
    id          BIGSERIAL PRIMARY KEY,
    task_id     BIGINT NOT NULL REFERENCES access_request(id) ON DELETE CASCADE,
    sql         TEXT,
    sql_hash    TEXT,
    status      TEXT CHECK (status IN ('RUNNING', 'DONE', 'FAILED', 'CANCELLED')),
    executed_by TEXT,                                -- the principal who ran it
    executed_at TIMESTAMPTZ DEFAULT now(),
    row_count   INT,                                 -- cleartext count, for the list preview
    columns     JSONB,
    ciphertext  BYTEA,                               -- AES-256-GCM(iv || rows JSON)
    error_code  TEXT,
    expires_at  TIMESTAMPTZ,                         -- expired rows are unreadable and purged
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_query_result_task ON query_result (task_id, id);
CREATE INDEX idx_query_result_expires ON query_result (expires_at);

-- Per-principal editor history: every run from the web editor, so a user can recall recent statements.
-- Convenience only -- distinct from audit_event, which is the security record.
CREATE TABLE query_history (
    id            BIGSERIAL PRIMARY KEY,
    principal     TEXT NOT NULL,
    datasource_id BIGINT,
    sql           TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX query_history_principal_idx ON query_history (principal, created_at DESC);

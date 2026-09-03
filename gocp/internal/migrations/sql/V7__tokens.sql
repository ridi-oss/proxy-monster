-- Wire tokens and the MCP OAuth authorization server.
--
-- Tokens and OAuth consent share one file because they are mutually coupled: an MCP token is bound to
-- the consent it was issued under, so `proxy_token.consent_id` references `oauth_consent`.
-- Every credential here is stored only as its SHA-256 hex hash.

-- A principal's standing grant to one client for one resource and scope. Revocation is a timestamp,
-- so an audit reader can still see a consent that once existed.
CREATE TABLE oauth_consent (
    id         BIGSERIAL PRIMARY KEY,
    principal  TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    resource   TEXT NOT NULL,
    scope      TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);
-- At most one live consent per (principal, client, resource, scope); a revoked one no longer blocks.
CREATE UNIQUE INDEX oauth_consent_active_tuple_uq
    ON oauth_consent (principal, client_id, resource, scope) WHERE revoked_at IS NULL;
CREATE INDEX oauth_consent_principal_idx ON oauth_consent (principal) WHERE revoked_at IS NULL;

-- A single-use authorization code. PKCE is mandatory: `code_challenge` is required, and the CHECK
-- pins it to the RFC 7636 length range so a truncated or absent challenge cannot persist.
CREATE TABLE oauth_authorization_code (
    id             BIGSERIAL PRIMARY KEY,
    code_hash      TEXT NOT NULL UNIQUE,
    client_id      TEXT NOT NULL,
    principal      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    resource       TEXT NOT NULL,
    scope          TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    consent_id     BIGINT NOT NULL REFERENCES oauth_consent(id),
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ,                     -- set on redemption; a used code never matches again
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (char_length(code_challenge) BETWEEN 43 AND 128)
);
CREATE INDEX oauth_authorization_code_expiry_idx
    ON oauth_authorization_code (expires_at) WHERE used_at IS NULL;

-- Wire credentials the proxy validates on the wire -> principal + base roles. Every token expires;
-- proxy-monster issues no persistent credential. Only the base-role snapshot lives here -- effective
-- roles (including a live access_grant) are resolved fresh at decision time.
--
-- `kind` is one of:
--   SESSION       daemon-held, silently refreshed by `pmon`.
--   USER          a named, expiring token a human generates for headless use.
--   MCP_ACCESS    an MCP access token, bound to its consent and resource.
--   MCP_REFRESH   its refresh partner, rotated within a `refresh_family`.
--
-- The CHECK makes the two shapes mutually exclusive: an MCP token MUST carry the full resource /
-- client / scope / family / consent set and no ambient roles (its authority comes from the consent),
-- while a non-MCP token must carry none of them. So a SESSION or USER token can never silently
-- acquire resource-bound MCP authority, and an MCP token can never carry a role snapshot.
CREATE TABLE proxy_token (
    id             BIGSERIAL PRIMARY KEY,
    token_hash     TEXT NOT NULL UNIQUE,            -- SHA-256 hex of the opaque token
    kind           TEXT NOT NULL,
    principal      TEXT NOT NULL,
    roles          JSONB NOT NULL DEFAULT '[]',     -- the base-role snapshot at issuance
    name           TEXT,                            -- label for a USER token; NULL for a session
    resource       TEXT,
    client_id      TEXT,
    scope          TEXT,
    refresh_family TEXT,
    consent_id     BIGINT REFERENCES oauth_consent(id),
    rotated_from   BIGINT REFERENCES proxy_token(id) ON DELETE SET NULL,
    rotated_at     TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    CONSTRAINT proxy_token_mcp_metadata_ck CHECK (
        (kind IN ('MCP_ACCESS', 'MCP_REFRESH')
            AND resource IS NOT NULL
            AND client_id IS NOT NULL
            AND scope IS NOT NULL
            AND refresh_family IS NOT NULL
            AND consent_id IS NOT NULL
            AND roles = '[]'::jsonb)
        OR
        (kind NOT IN ('MCP_ACCESS', 'MCP_REFRESH')
            AND resource IS NULL
            AND client_id IS NULL
            AND scope IS NULL
            AND refresh_family IS NULL
            AND consent_id IS NULL
            AND rotated_from IS NULL
            AND rotated_at IS NULL)
    )
);
CREATE INDEX proxy_token_principal_idx ON proxy_token (principal);
CREATE INDEX proxy_token_mcp_family_idx
    ON proxy_token (refresh_family) WHERE kind IN ('MCP_ACCESS', 'MCP_REFRESH');
CREATE INDEX proxy_token_mcp_consent_idx
    ON proxy_token (consent_id) WHERE kind IN ('MCP_ACCESS', 'MCP_REFRESH');

-- Idempotency for an MCP mutation tool: the first call records its request hash and response, and a
-- retry with the same key returns the stored response instead of applying the mutation twice.
CREATE TABLE mcp_mutation_idempotency (
    principal       TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    tool_name       TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_hash    TEXT NOT NULL,
    response_json   JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (principal, client_id, tool_name, idempotency_key)
);

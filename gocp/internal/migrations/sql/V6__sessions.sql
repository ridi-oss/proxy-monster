-- Login sessions and wire credentials.
--
-- Every secret in this file is stored ONLY as a SHA-256 hex hash or AES-256-GCM ciphertext; no
-- plaintext token or refresh token is ever persisted.

-- One row per in-flight `pmon login` device-authorization attempt (RFC 8628). Short-lived by design:
-- rows are deleted once `expires_at` passes (DeviceLoginStore.purgeExpired).
CREATE TABLE device_login (
    id           BIGSERIAL PRIMARY KEY,
    -- The opaque polling secret. `pmon` polls by `handle` and nothing else ever sees it.
    handle       TEXT NOT NULL UNIQUE,
    -- The human-facing verification code. The browser opens {cp}/device?user_code=<user_code> and the
    -- human confirms this short code, then picks SSO or debug on the page -- which approves the
    -- handle. Kept distinct from `handle` so the polling secret never rides in a browser URL.
    user_code    TEXT,
    -- The IdP's device_code, or NULL under the PM_AUTH_DEBUG short-circuit, which pre-approves a
    -- synthetic row with no IdP round trip. Never leaves the server.
    device_code  TEXT,
    interval_sec INTEGER NOT NULL DEFAULT 5,
    ttl_seconds  BIGINT NOT NULL,                    -- the wire SESSION token TTL `pmon` asked for
    status       TEXT NOT NULL DEFAULT 'PENDING',    -- PENDING | APPROVED
    principal    TEXT,
    -- The IdP refresh token captured when the SSO choice completes, AES-256-GCM-encrypted at rest via
    -- ResultCrypto and carried onto the minted session at poll so its liveness revalidation keeps
    -- working. NULL for a debug login, when the client granted no offline_access, or when
    -- PM_RESULT_KEY is unset.
    refresh_token_enc BYTEA,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);
-- Supports the expiry sweep (DELETE ... WHERE expires_at <= now()).
CREATE INDEX idx_device_login_expires_at ON device_login (expires_at);
-- One in-flight login per user_code (the page looks the handle up by it). Partial so the NULLs on
-- rows that never got a code do not collide.
CREATE UNIQUE INDEX idx_device_login_user_code ON device_login (user_code) WHERE user_code IS NOT NULL;

-- One row per login session, for both session kinds: a `pmon` daemon login and a web console login.
-- Two clocks bound a session -- `idle_expires_at` slides on activity, `absolute_expires_at` is the hard
-- cap on silent renewal. Past the absolute cap the client must log in again.
CREATE TABLE principal_session (
    id                  BIGSERIAL PRIMARY KEY,
    kind                TEXT NOT NULL,
    principal           TEXT NOT NULL,
    handle              TEXT,                          -- the originating device_login.handle, if any
    -- The web cookie's opaque session key. NULL for a daemon session.
    session_key         TEXT,
    device_id           TEXT,
    -- The IdP refresh token (present only when the client granted `offline_access`),
    -- AES-256-GCM-encrypted at rest via ResultCrypto. NULL when there is no refresh token or no
    -- PM_RESULT_KEY configured.
    refresh_token_enc   BYTEA,
    -- The bearer renewal secret for POST /auth/session/renew: a high-entropy, mint-once secret
    -- returned only once in the device-poll result, and stored ONLY as its SHA-256 hex hash.
    renewal_token_hash  TEXT,
    ttl_seconds         BIGINT,
    idle_expires_at     TIMESTAMPTZ,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    -- The stale-while-revalidate IdP liveness check: a session whose IdP-side identity went away is
    -- marked INACTIVE and stops renewing.
    last_idp_check_at   TIMESTAMPTZ,
    liveness_status     TEXT NOT NULL DEFAULT 'ACTIVE',   -- ACTIVE | INACTIVE
    last_seen_at        TIMESTAMPTZ,
    ended_at            TIMESTAMPTZ,
    ended_reason        TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_principal_session_principal ON principal_session (principal, created_at DESC);
CREATE INDEX idx_principal_session_handle ON principal_session (handle);
CREATE INDEX idx_principal_session_renewal_hash ON principal_session (renewal_token_hash);
CREATE INDEX idx_principal_session_active ON principal_session (principal, kind) WHERE ended_at IS NULL;
CREATE UNIQUE INDEX idx_principal_session_session_key
    ON principal_session (session_key) WHERE session_key IS NOT NULL;

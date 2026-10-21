-- The daemon session a token was minted from, so ending the session revokes its tokens.
ALTER TABLE proxy_token ADD COLUMN principal_session_id BIGINT REFERENCES principal_session(id) ON DELETE SET NULL;
CREATE INDEX proxy_token_principal_session_idx ON proxy_token (principal_session_id) WHERE principal_session_id IS NOT NULL;
-- A retired wire token keeps its open connections but opens no new one.
ALTER TABLE proxy_token ADD COLUMN retired_at TIMESTAMPTZ;

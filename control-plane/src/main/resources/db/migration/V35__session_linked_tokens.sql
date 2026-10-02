-- The daemon session a token was minted from (a pmon wire token or an exchanged MCP token), so ending
-- that session revokes exactly its tokens.
ALTER TABLE proxy_token ADD COLUMN principal_session_id BIGINT REFERENCES principal_session(id) ON DELETE SET NULL;
CREATE INDEX proxy_token_principal_session_idx ON proxy_token (principal_session_id) WHERE principal_session_id IS NOT NULL;

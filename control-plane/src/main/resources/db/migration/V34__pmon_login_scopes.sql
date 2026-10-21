-- Scopes beyond mcp:read and mcp:query last until elevated_until, stamped at approval.
ALTER TABLE device_login ADD COLUMN scopes TEXT NOT NULL DEFAULT 'mcp:query mcp:read';
ALTER TABLE device_login ADD COLUMN elevated_until TIMESTAMPTZ;
ALTER TABLE principal_session ADD COLUMN scopes TEXT;
ALTER TABLE principal_session ADD COLUMN elevated_until TIMESTAMPTZ;
UPDATE principal_session SET scopes = 'mcp:query mcp:read' WHERE kind = 'DAEMON';

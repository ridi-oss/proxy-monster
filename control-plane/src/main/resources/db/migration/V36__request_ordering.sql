ALTER TABLE access_request ADD COLUMN source TEXT NOT NULL DEFAULT 'console';
ALTER TABLE access_request ADD COLUMN scope TEXT;
ALTER TABLE access_request ADD COLUMN file_key TEXT;
ALTER TABLE access_request ADD COLUMN content_hash TEXT;
ALTER TABLE access_request ADD COLUMN change_key TEXT;
ALTER TABLE access_request ADD COLUMN merged_at TIMESTAMPTZ;

CREATE INDEX idx_access_request_scope ON access_request (scope, change_key) WHERE scope IS NOT NULL;

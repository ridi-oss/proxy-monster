-- The SQL text's own hash beside the normalized content_hash, which a normalizer upgrade can change.
ALTER TABLE access_request ADD COLUMN raw_hash TEXT;
UPDATE access_request SET raw_hash = substr(content_hash, 3), content_hash = NULL WHERE content_hash LIKE 'r:%';
UPDATE access_request SET content_hash = substr(content_hash, 3) WHERE content_hash LIKE 'n:%';
-- A change key is the sha256 of the file key, a newline, and the content hash or else the raw hash.
UPDATE access_request
SET change_key = encode(sha256(convert_to(file_key || E'\n' || coalesce(content_hash, raw_hash), 'UTF8')), 'hex')
WHERE source = 'github' AND file_key IS NOT NULL AND coalesce(content_hash, raw_hash) IS NOT NULL;

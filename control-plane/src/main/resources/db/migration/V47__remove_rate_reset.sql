-- Rate resets are gone. Past RATE_RESET requests stay as history; one still pending is closed.
INSERT INTO request_event (request_id, kind, actor, revision, origin)
SELECT id, 'cancelled', NULL, revision, 'console' FROM access_request WHERE kind = 'RATE_RESET' AND status = 'PENDING';
UPDATE access_request SET status = 'CANCELLED' WHERE kind = 'RATE_RESET' AND status = 'PENDING';
DROP TABLE result_rate_reset;

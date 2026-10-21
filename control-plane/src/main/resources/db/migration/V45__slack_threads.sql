-- Each Slack thread receives the request's later timeline entries, in order, past this cursor.
ALTER TABLE notification_message ADD COLUMN last_event_id BIGINT NOT NULL DEFAULT 0;
UPDATE notification_message m
SET last_event_id = coalesce((SELECT max(e.id) FROM request_event e WHERE e.request_id = m.task_id), 0);

-- A comment written as a Slack reply: the thread it was written in (never copied back there) and the reply itself.
ALTER TABLE request_event ADD COLUMN source_thread TEXT;
ALTER TABLE request_event ADD COLUMN slack_ref TEXT;
ALTER TABLE request_event ADD COLUMN edited_at TIMESTAMPTZ;
ALTER TABLE request_event ADD COLUMN deleted_at TIMESTAMPTZ;
CREATE UNIQUE INDEX request_event_slack_ref_idx ON request_event (slack_ref) WHERE slack_ref IS NOT NULL;

-- The copies of an entry posted into threads, so an edit or delete of the original follows them.
CREATE TABLE request_event_post (
    event_id     BIGINT NOT NULL REFERENCES request_event(id) ON DELETE CASCADE,
    external_ref TEXT   NOT NULL,
    PRIMARY KEY (event_id, external_ref)
);

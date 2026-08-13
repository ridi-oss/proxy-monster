-- A recipient can relate to one task both as its requester (a task.submitted receipt) and as an approver (a
-- task.requested message) — self-approval. Each is its own thread that is delivered and later edited
-- independently, so the outbox and the delivered-message record are keyed by `kind` ('requester' |
-- 'approver'), not by recipient alone. Without this the second message to a shared recipient is deduped away
-- on delivery. Rows created before this migration are approver-side — the only kind that existed.
ALTER TABLE notification_outbox ADD COLUMN kind TEXT NOT NULL DEFAULT 'approver';
ALTER TABLE notification_message ADD COLUMN kind TEXT NOT NULL DEFAULT 'approver';

ALTER TABLE notification_outbox DROP CONSTRAINT notification_outbox_unique;
ALTER TABLE notification_outbox ADD CONSTRAINT notification_outbox_unique
    UNIQUE (task_id, event, transport, recipient, kind);

ALTER TABLE notification_message DROP CONSTRAINT notification_message_unique;
ALTER TABLE notification_message ADD CONSTRAINT notification_message_unique
    UNIQUE (task_id, transport, recipient, kind);

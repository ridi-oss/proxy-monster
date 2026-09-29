-- Out-of-band task notifications: a durable outbox the delivery loop drains, the external handle a later
-- event edits in place, and the recipient's own language.
--
-- The outbox row is written in the SAME transaction as the task state change it describes, so a crash can
-- never leave a request approved with nobody told. Delivery itself is best-effort and never touches the
-- task: the console is the system of record and a notification is a courtesy.

-- The recipient's language, set from the console's own locale toggle and on login. A display preference,
-- never an authorization input -- no policy reads it and nothing fails closed on it. NULL means the user has
-- never expressed one, so delivery falls back to the instance default and then to English.
ALTER TABLE app_user ADD COLUMN locale TEXT;

CREATE TABLE notification_outbox (
    id           BIGSERIAL PRIMARY KEY,
    task_id      BIGINT NOT NULL REFERENCES access_request(id) ON DELETE CASCADE,
    -- task.requested | task.decided | task.executed | task.failed | task.cancelled
    event        TEXT NOT NULL,
    transport    TEXT NOT NULL,
    -- The principal to reach. Free text, matching app_user.principal, which is itself not an FK target
    -- (V1) -- a principal_role-only identity holds roles without ever having a directory row.
    recipient    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'PENDING',
    attempts     INT  NOT NULL DEFAULT 0,
    -- When the drainer may next claim this row: now for a first attempt, later for a backed-off retry.
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT notification_outbox_status_check
        CHECK (status IN ('PENDING', 'SENT', 'DEAD')),
    -- One row per (task, event, transport, recipient). An event emitted twice for one recipient -- a retried
    -- request creation, a redelivery after a partial failure -- collapses onto the same row instead of
    -- sending twice.
    CONSTRAINT notification_outbox_unique UNIQUE (task_id, event, transport, recipient)
);

-- The drainer's claim query: due PENDING rows in insertion order. Partial, so SENT/DEAD rows (the bulk over
-- time) cost nothing to skip.
CREATE INDEX idx_notification_outbox_due
    ON notification_outbox (next_attempt_at, id) WHERE status = 'PENDING';

-- Where a delivered message landed, so a later event edits it rather than piling on. For Slack that is
-- "channel:ts"; for a transport with no edit primitive the ref is still recorded and the update sends a new
-- message. One row per (task, transport, recipient) -- the whole point is that every event about one task
-- rewrites the SAME message for that person.
CREATE TABLE notification_message (
    id           BIGSERIAL PRIMARY KEY,
    task_id      BIGINT NOT NULL REFERENCES access_request(id) ON DELETE CASCADE,
    transport    TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    external_ref TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT notification_message_unique UNIQUE (task_id, transport, recipient)
);

-- The GitHub review an event came from: a review is recorded once per request and kind.
ALTER TABLE request_event ADD COLUMN github_review_id TEXT;
CREATE UNIQUE INDEX request_event_github_review_idx ON request_event (request_id, kind, github_review_id)
    WHERE github_review_id IS NOT NULL;

UPDATE request_event e SET github_review_id = r.approved_review_id
FROM access_request r
WHERE r.id = e.request_id AND r.approved_review_id IS NOT NULL
  AND e.id = (SELECT max(id) FROM request_event WHERE request_id = r.id AND kind = 'approved');

ALTER TABLE request_event DROP CONSTRAINT request_event_kind_check;
ALTER TABLE request_event ADD CONSTRAINT request_event_kind_check CHECK (kind IN (
    'requested', 'edited', 'approved', 'rejected', 'unapproved', 'expired', 'withdrawn', 'closed',
    'ran', 'executed', 'failed', 'cancelled', 'comment', 'lgtm', 'cc_added', 'cc_removed',
    'code_approved', 'code_changes_requested', 'code_review_dismissed'));

-- CC changes and code reviews redraw messages through one event.
UPDATE notification_outbox SET event = 'task.redrawn' WHERE event = 'task.cc_changed';

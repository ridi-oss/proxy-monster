-- No Slack message, in a channel or a DM, is sent about a private request.
ALTER TABLE access_request ADD COLUMN private BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE request_event DROP CONSTRAINT request_event_kind_check;
ALTER TABLE request_event ADD CONSTRAINT request_event_kind_check CHECK (kind IN (
    'requested', 'edited', 'approved', 'rejected', 'unapproved', 'expired', 'withdrawn', 'closed',
    'ran', 'executed', 'failed', 'cancelled', 'comment', 'lgtm', 'cc_added', 'cc_removed',
    'code_approved', 'code_changes_requested', 'code_review_dismissed', 'made_private'));

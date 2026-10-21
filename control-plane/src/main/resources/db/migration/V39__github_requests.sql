-- A request filed from a pull request: the file's path, the PR it came from, and the schema its run opens on.
ALTER TABLE access_request ADD COLUMN path TEXT;
ALTER TABLE access_request ADD COLUMN pr_url TEXT;
ALTER TABLE access_request ADD COLUMN repository TEXT;
ALTER TABLE access_request ADD COLUMN pr INTEGER;
ALTER TABLE access_request ADD COLUMN default_schema TEXT;
ALTER TABLE access_request ADD COLUMN pr_auto_merge BOOLEAN NOT NULL DEFAULT FALSE;
-- The head the request was filed for, and the merge commit recorded when the pull request merged.
ALTER TABLE access_request ADD COLUMN head_sha TEXT;
ALTER TABLE access_request ADD COLUMN merge_sha TEXT;
-- The review an approval came from, so only that review's dismissal withdraws it.
ALTER TABLE access_request ADD COLUMN approved_review_id TEXT;
-- The head of the scope's latest filing, set on every request of the pull request in that scope.
ALTER TABLE access_request ADD COLUMN filed_head TEXT;
-- How the latest filing orders file keys, set with filed_head: 'numeric' or 'string'.
ALTER TABLE access_request ADD COLUMN key_order TEXT;

CREATE INDEX idx_access_request_pull_request ON access_request (repository, pr) WHERE repository IS NOT NULL;

-- ALREADY_RAN: the request's key already ran in its scope, from another pull request.
ALTER TABLE access_request DROP CONSTRAINT access_request_status_shape;
ALTER TABLE access_request ADD CONSTRAINT access_request_status_shape CHECK (
    (kind IN ('ROLE', 'RATE_RESET') AND status IN ('PENDING', 'APPROVED', 'REJECTED'))
 OR (kind = 'QUERY' AND status IN ('DRAFT', 'PENDING', 'APPROVED', 'REJECTED', 'EXECUTING',
                                   'EXECUTED', 'FAILED', 'CANCELLED', 'DELETED', 'ALREADY_RAN'))
);

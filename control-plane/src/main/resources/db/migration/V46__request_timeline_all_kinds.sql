-- Role and rate-reset requests are workflow requests too.
UPDATE access_request SET creator_kind = 'WORKFLOW' WHERE creator_kind IS NULL;
ALTER TABLE access_request ALTER COLUMN creator_kind SET NOT NULL;

-- Role and rate-reset requests get a timeline too.
INSERT INTO request_event (request_id, kind, actor, revision, origin, created_at)
SELECT * FROM (
    SELECT id, 'requested' AS kind, principal, revision, source, created_at FROM access_request
    WHERE kind IN ('ROLE', 'RATE_RESET')
    UNION ALL
    SELECT id, CASE WHEN status = 'REJECTED' THEN 'rejected' ELSE 'approved' END, decided_by, revision, source, decided_at
    FROM access_request
    WHERE kind IN ('ROLE', 'RATE_RESET') AND decided_at IS NOT NULL AND decided_by IS NOT NULL
) e
ORDER BY e.created_at, e.kind <> 'requested';

-- Their deciders took part, as RequestEvents.record would have recorded.
INSERT INTO request_participant (request_id, principal, kind)
SELECT id, decided_by, 'approver' FROM access_request
WHERE kind IN ('ROLE', 'RATE_RESET') AND decided_by IS NOT NULL AND decided_by <> principal
  AND decided_by NOT LIKE 'system:%'
ON CONFLICT DO NOTHING;

-- The requester can close a role or rate-reset request that is still pending.
ALTER TABLE access_request DROP CONSTRAINT access_request_status_shape;
ALTER TABLE access_request ADD CONSTRAINT access_request_status_shape CHECK (
    (kind IN ('ROLE', 'RATE_RESET') AND status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED'))
 OR (kind = 'QUERY' AND status IN ('DRAFT', 'PENDING', 'APPROVED', 'REJECTED', 'EXECUTING',
                                   'EXECUTED', 'FAILED', 'CANCELLED', 'DELETED', 'ALREADY_RAN'))
);

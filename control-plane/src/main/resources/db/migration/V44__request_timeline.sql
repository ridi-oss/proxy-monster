-- A query request's timeline: comments, LGTMs, CC changes, and its state changes, in order.
CREATE TABLE request_event (
    id         BIGSERIAL PRIMARY KEY,
    request_id BIGINT NOT NULL REFERENCES access_request(id) ON DELETE CASCADE,
    kind       TEXT   NOT NULL,
    -- Null for an event the system made, such as an expiry or a run ending.
    actor      TEXT,
    body       TEXT,
    revision   INT,
    origin     TEXT   NOT NULL DEFAULT 'console',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT request_event_kind_check CHECK (kind IN (
        'requested', 'edited', 'approved', 'rejected', 'unapproved', 'expired', 'withdrawn', 'closed',
        'ran', 'executed', 'failed', 'cancelled', 'comment', 'lgtm', 'cc_added', 'cc_removed'))
);
CREATE INDEX request_event_request_idx ON request_event (request_id, id);

INSERT INTO request_event (request_id, kind, actor, revision, origin, created_at)
SELECT id, 'requested', principal, 1, source, created_at FROM access_request
WHERE kind = 'QUERY' AND creator_kind = 'WORKFLOW'
UNION ALL
SELECT id, CASE WHEN status = 'REJECTED' THEN 'rejected' ELSE 'approved' END, decided_by, revision, source, decided_at
FROM access_request
WHERE kind = 'QUERY' AND creator_kind = 'WORKFLOW' AND decided_at IS NOT NULL AND decided_by IS NOT NULL
UNION ALL
SELECT id, lower(status), NULL, revision, source, coalesce(executed_at, executing_at)
FROM access_request
WHERE kind = 'QUERY' AND creator_kind = 'WORKFLOW' AND status IN ('EXECUTED', 'FAILED')
  AND coalesce(executed_at, executing_at) IS NOT NULL
ORDER BY 6;

-- CCs read and comment on a request, and any participant manages its CCs.
UPDATE policy SET cedar_src = $$permit (
  principal in Role::"system:admin",
  action in
    [Action::"task.approve",
     Action::"task.run",
     Action::"task.comment",
     Action::"task.cc",
     Action::"task.read",
     Action::"grant.revoke",
     Action::"task.request",
     Action::"task.cancel",
     Action::"task.delete",
     Action::"task.force_run"],
  resource
);
$$ WHERE id = -3 AND origin = 'SYSTEM';

INSERT INTO policy (id, system_key, name, cedar_src, enabled, origin, updated_by, updated_at) VALUES
    (-27, 'task.cc-parties', 'system:task-cc-parties',
     $$permit (
  principal is User,
  action in [Action::"task.read", Action::"task.comment", Action::"task.cc"],
  resource
)
when
{
  resource is Request &&
  (resource.requester == principal ||
   (resource has ccs && resource.ccs.contains(principal)))
};
$$, TRUE, 'SYSTEM', 'migration:V44', now());

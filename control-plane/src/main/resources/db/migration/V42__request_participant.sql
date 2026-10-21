-- Who besides the requester took part in a query request: notified or acting approvers, and CCs.
-- Approver rows only drive the history list and are never read for authorization.
CREATE TABLE request_participant (
    request_id BIGINT NOT NULL REFERENCES access_request(id) ON DELETE CASCADE,
    principal  TEXT   NOT NULL,
    kind       TEXT   NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, principal, kind),
    CONSTRAINT request_participant_kind_check CHECK (kind IN ('approver', 'cc'))
);
CREATE INDEX request_participant_principal_idx ON request_participant (principal);

INSERT INTO request_participant (request_id, principal, kind)
SELECT o.task_id, o.recipient, 'approver' FROM notification_outbox o
WHERE o.event = 'task.requested' AND o.kind = 'approver' AND o.transport = 'slack'
UNION
SELECT ar.id, ar.decided_by, 'approver' FROM access_request ar
WHERE ar.kind = 'QUERY' AND ar.creator_kind = 'WORKFLOW' AND ar.decided_by IS NOT NULL AND ar.decided_by <> ar.principal
UNION
SELECT qr.task_id, qr.executed_by, 'approver' FROM query_result qr
JOIN access_request ar ON ar.id = qr.task_id
WHERE ar.kind = 'QUERY' AND ar.creator_kind = 'WORKFLOW' AND qr.executed_by IS NOT NULL AND qr.executed_by <> ar.principal
ON CONFLICT DO NOTHING;

-- name: RecordRequestEvent :one
INSERT INTO request_event (request_id, kind, actor, body, revision, origin)
SELECT ar.id, @kind::text, sqlc.narg(actor)::text, sqlc.narg(body)::text, ar.revision, @origin::text FROM access_request ar
WHERE ar.id = @request_id::bigint AND ar.creator_kind = 'WORKFLOW'
RETURNING request_event.id;

-- name: AddApprover :exec
INSERT INTO request_participant (request_id, principal, kind)
SELECT @request_id::bigint, @principal::text, 'approver'
WHERE @principal::text <> (SELECT principal FROM access_request WHERE id = @request_id::bigint)
ON CONFLICT DO NOTHING;

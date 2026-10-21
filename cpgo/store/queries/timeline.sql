-- name: RecordRequestEvent :one
INSERT INTO request_event (request_id, kind, actor, body, revision, origin)
SELECT ar.id, @kind::text, sqlc.narg(actor)::text, sqlc.narg(body)::text, ar.revision, @origin::text FROM access_request ar
WHERE ar.id = @request_id::bigint AND ar.creator_kind = 'WORKFLOW'
RETURNING request_event.id, request_event.kind, request_event.actor, request_event.body, request_event.revision,
          request_event.origin, request_event.created_at, request_event.edited_at, request_event.deleted_at;

-- name: AddApprover :exec
INSERT INTO request_participant (request_id, principal, kind)
SELECT @request_id::bigint, @principal::text, 'approver'
WHERE @principal::text <> (SELECT principal FROM access_request WHERE id = @request_id::bigint)
ON CONFLICT DO NOTHING;

-- name: RequestTimeline :many
SELECT id, kind, actor, body, revision, origin, created_at, edited_at, deleted_at FROM request_event
WHERE request_id = $1 ORDER BY id;

-- name: RequestParticipants :many
SELECT DISTINCT principal FROM request_participant WHERE request_id = $1 ORDER BY principal;

-- name: AddCC :exec
INSERT INTO request_participant (request_id, principal, kind)
SELECT @request_id::bigint, @principal::text, 'cc'
WHERE @principal::text <> (SELECT principal FROM access_request WHERE id = @request_id::bigint)
ON CONFLICT DO NOTHING;

-- name: RemoveCC :execrows
DELETE FROM request_participant WHERE request_id = $1 AND principal = $2 AND kind = 'cc';

-- name: PeopleByPrincipal :many
SELECT principal, display_name, email FROM app_user WHERE principal = ANY(@principals::text[]);

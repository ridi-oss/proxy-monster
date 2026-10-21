-- name: AccessRequests :many
SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
       ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by,
       (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by,
       ar.decided_at, ar.rejection_reason, ar.created_at, ar.kind,
       (SELECT string_agg(qr.sql, E';\n' ORDER BY qr.ordinal) FROM query_result qr WHERE qr.task_id = ar.id) AS sql,
       (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS sql_hash,
       (SELECT count(*) FROM query_result qr WHERE qr.task_id = ar.id) AS statement_count,
       ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
       ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
       ar.statement_carries_protected_literal, ar.source, ar.scope, ar.change_key, ar.merged_at,
       ar.revision, ar.revised_at, ar.content_hash,
       ar.file_key, ar.path, ar.pr_url, ar.repository, ar.pr, ar.default_schema, ar.pr_auto_merge,
       ar.head_sha, ar.merge_sha, ar.approved_review_id, ar.filed_head, ar.key_order, ar.force_run, ar.force_run_by,
       (SELECT coalesce(array_agg(p.principal ORDER BY p.principal), '{}') FROM request_participant p
        WHERE p.request_id = ar.id AND p.kind = 'cc')::text[] AS ccs
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
LEFT JOIN datasource d ON d.id = ar.datasource_id
WHERE ar.kind IN ('ROLE', 'RATE_RESET') ORDER BY ar.created_at DESC;

-- name: AccessRequestsByStatus :many
SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
       ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by,
       (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by,
       ar.decided_at, ar.rejection_reason, ar.created_at, ar.kind,
       (SELECT string_agg(qr.sql, E';\n' ORDER BY qr.ordinal) FROM query_result qr WHERE qr.task_id = ar.id) AS sql,
       (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS sql_hash,
       (SELECT count(*) FROM query_result qr WHERE qr.task_id = ar.id) AS statement_count,
       ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
       ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
       ar.statement_carries_protected_literal, ar.source, ar.scope, ar.change_key, ar.merged_at,
       ar.revision, ar.revised_at, ar.content_hash,
       ar.file_key, ar.path, ar.pr_url, ar.repository, ar.pr, ar.default_schema, ar.pr_auto_merge,
       ar.head_sha, ar.merge_sha, ar.approved_review_id, ar.filed_head, ar.key_order, ar.force_run, ar.force_run_by,
       (SELECT coalesce(array_agg(p.principal ORDER BY p.principal), '{}') FROM request_participant p
        WHERE p.request_id = ar.id AND p.kind = 'cc')::text[] AS ccs
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
LEFT JOIN datasource d ON d.id = ar.datasource_id
WHERE ar.kind IN ('ROLE', 'RATE_RESET') AND ar.status = $1 ORDER BY ar.created_at DESC;

-- name: OwnApprovals :many
SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
       ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by,
       (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by,
       ar.decided_at, ar.rejection_reason, ar.created_at, ar.kind,
       (SELECT string_agg(qr.sql, E';\n' ORDER BY qr.ordinal) FROM query_result qr WHERE qr.task_id = ar.id) AS sql,
       (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS sql_hash,
       (SELECT count(*) FROM query_result qr WHERE qr.task_id = ar.id) AS statement_count,
       ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
       ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
       ar.statement_carries_protected_literal, ar.source, ar.scope, ar.change_key, ar.merged_at,
       ar.revision, ar.revised_at, ar.content_hash,
       ar.file_key, ar.path, ar.pr_url, ar.repository, ar.pr, ar.default_schema, ar.pr_auto_merge,
       ar.head_sha, ar.merge_sha, ar.approved_review_id, ar.filed_head, ar.key_order, ar.force_run, ar.force_run_by,
       (SELECT coalesce(array_agg(p.principal ORDER BY p.principal), '{}') FROM request_participant p
        WHERE p.request_id = ar.id AND p.kind = 'cc')::text[] AS ccs
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
LEFT JOIN datasource d ON d.id = ar.datasource_id
WHERE ar.kind = 'QUERY' AND ar.creator_kind = 'WORKFLOW' AND ar.principal = $1 ORDER BY ar.created_at DESC;

-- name: OwnApprovalsByStatus :many
SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
       ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by,
       (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by,
       ar.decided_at, ar.rejection_reason, ar.created_at, ar.kind,
       (SELECT string_agg(qr.sql, E';\n' ORDER BY qr.ordinal) FROM query_result qr WHERE qr.task_id = ar.id) AS sql,
       (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS sql_hash,
       (SELECT count(*) FROM query_result qr WHERE qr.task_id = ar.id) AS statement_count,
       ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
       ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
       ar.statement_carries_protected_literal, ar.source, ar.scope, ar.change_key, ar.merged_at,
       ar.revision, ar.revised_at, ar.content_hash,
       ar.file_key, ar.path, ar.pr_url, ar.repository, ar.pr, ar.default_schema, ar.pr_auto_merge,
       ar.head_sha, ar.merge_sha, ar.approved_review_id, ar.filed_head, ar.key_order, ar.force_run, ar.force_run_by,
       (SELECT coalesce(array_agg(p.principal ORDER BY p.principal), '{}') FROM request_participant p
        WHERE p.request_id = ar.id AND p.kind = 'cc')::text[] AS ccs
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
LEFT JOIN datasource d ON d.id = ar.datasource_id
WHERE ar.kind = 'QUERY' AND ar.creator_kind = 'WORKFLOW' AND ar.principal = $1 AND ar.status = $2 ORDER BY ar.created_at DESC;

-- name: AccessGrants :many
SELECT ag.id, ag.principal, ag.role_id, r.name AS role_name, ag.granted_by, ag.granted_at, ag.expires_at, ag.revoked_at
FROM access_grant ag JOIN app_role r ON r.id = ag.role_id AND r.deleted_at IS NULL WHERE true
ORDER BY ag.granted_at DESC;

-- name: AccessGrantsOf :many
SELECT ag.id, ag.principal, ag.role_id, r.name AS role_name, ag.granted_by, ag.granted_at, ag.expires_at, ag.revoked_at
FROM access_grant ag JOIN app_role r ON r.id = ag.role_id AND r.deleted_at IS NULL WHERE true AND ag.principal = $1
ORDER BY ag.granted_at DESC;

-- name: LiveAccessGrants :many
SELECT ag.id, ag.principal, ag.role_id, r.name AS role_name, ag.granted_by, ag.granted_at, ag.expires_at, ag.revoked_at
FROM access_grant ag JOIN app_role r ON r.id = ag.role_id AND r.deleted_at IS NULL WHERE true AND ag.revoked_at IS NULL AND (ag.expires_at IS NULL OR ag.expires_at > now())
ORDER BY ag.granted_at DESC;

-- name: LiveAccessGrantsOf :many
SELECT ag.id, ag.principal, ag.role_id, r.name AS role_name, ag.granted_by, ag.granted_at, ag.expires_at, ag.revoked_at
FROM access_grant ag JOIN app_role r ON r.id = ag.role_id AND r.deleted_at IS NULL WHERE true AND ag.principal = $1 AND ag.revoked_at IS NULL AND (ag.expires_at IS NULL OR ag.expires_at > now())
ORDER BY ag.granted_at DESC;

-- name: AccessRequest :one
SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
       ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by,
       (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by,
       ar.decided_at, ar.rejection_reason, ar.created_at, ar.kind,
       (SELECT string_agg(qr.sql, E';\n' ORDER BY qr.ordinal) FROM query_result qr WHERE qr.task_id = ar.id) AS sql,
       (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS sql_hash,
       (SELECT count(*) FROM query_result qr WHERE qr.task_id = ar.id) AS statement_count,
       ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
       ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
       ar.statement_carries_protected_literal, ar.source, ar.scope, ar.change_key, ar.merged_at,
       ar.revision, ar.revised_at, ar.content_hash,
       ar.file_key, ar.path, ar.pr_url, ar.repository, ar.pr, ar.default_schema, ar.pr_auto_merge,
       ar.head_sha, ar.merge_sha, ar.approved_review_id, ar.filed_head, ar.key_order, ar.force_run, ar.force_run_by,
       (SELECT coalesce(array_agg(p.principal ORDER BY p.principal), '{}') FROM request_participant p
        WHERE p.request_id = ar.id AND p.kind = 'cc')::text[] AS ccs
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
LEFT JOIN datasource d ON d.id = ar.datasource_id
WHERE ar.id = $1;

-- name: DatasourceLive :one
SELECT EXISTS (SELECT 1 FROM datasource WHERE id = $1 AND deleted_at IS NULL);

-- name: CreateRoleRequest :one
INSERT INTO access_request (principal, role_id, datasource_id, reason, requested_duration_sec, creator_kind)
VALUES ($1, $2, $3, $4, $5, 'WORKFLOW') RETURNING id;

-- name: RoleNameOf :one
SELECT name FROM app_role WHERE id = $1;

-- name: DatasourceTags :one
SELECT tags FROM datasource WHERE id = $1;

-- name: ApproveRequest :execrows
UPDATE access_request SET status = 'APPROVED', decided_by = $1, decided_at = now()
WHERE id = $2 AND status = 'PENDING';

-- name: InsertGrant :one
INSERT INTO access_grant (request_id, principal, role_id, granted_by, granted_at, expires_at)
VALUES ($1, $2, $3, $4, now(), $5) RETURNING id;

-- name: RejectRequest :execrows
UPDATE access_request SET status = 'REJECTED', rejection_reason = $1, decided_by = $2,
decided_at = now() WHERE id = $3 AND status = 'PENDING';

-- name: AccessGrant :one
SELECT ag.id, ag.principal, ag.role_id, r.name AS role_name, ag.granted_by, ag.granted_at, ag.expires_at, ag.revoked_at
FROM access_grant ag JOIN app_role r ON r.id = ag.role_id AND r.deleted_at IS NULL WHERE ag.id = $1;

-- name: RevokeGrant :execrows
UPDATE access_grant SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: InvolvedRequests :many
SELECT ar.id, ar.principal, ar.role_id, r.name AS role_name, ar.datasource_id, d.name AS datasource_name,
       ar.reason, ar.requested_duration_sec, ar.status, ar.decided_by,
       (SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by,
       ar.decided_at, ar.rejection_reason, ar.created_at, ar.kind,
       (SELECT string_agg(qr.sql, E';\n' ORDER BY qr.ordinal) FROM query_result qr WHERE qr.task_id = ar.id) AS sql,
       (SELECT qr.sql_hash FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS sql_hash,
       (SELECT count(*) FROM query_result qr WHERE qr.task_id = ar.id) AS statement_count,
       ar.deny_reason, ar.source_decision_id, ar.title, ar.evaluated_decision,
       ar.approved_at, ar.executing_at, ar.executed_at, ar.execute_as, ar.creator_kind,
       ar.statement_carries_protected_literal, ar.source, ar.scope, ar.change_key, ar.merged_at,
       ar.revision, ar.revised_at, ar.content_hash,
       ar.file_key, ar.path, ar.pr_url, ar.repository, ar.pr, ar.default_schema, ar.pr_auto_merge,
       ar.head_sha, ar.merge_sha, ar.approved_review_id, ar.filed_head, ar.key_order, ar.force_run, ar.force_run_by,
       (SELECT coalesce(array_agg(p.principal ORDER BY p.principal), '{}') FROM request_participant p
        WHERE p.request_id = ar.id AND p.kind = 'cc')::text[] AS ccs
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
LEFT JOIN datasource d ON d.id = ar.datasource_id
WHERE ar.creator_kind = 'WORKFLOW'
  AND (ar.principal = @principal::text OR EXISTS (
       SELECT 1 FROM request_participant p WHERE p.request_id = ar.id AND p.principal = @principal::text))
ORDER BY ar.created_at DESC LIMIT 200;

-- name: CloseRequest :execrows
UPDATE access_request ar SET status = 'CANCELLED'
WHERE ar.id = $1 AND ar.creator_kind = 'WORKFLOW' AND (ar.status = 'PENDING' OR (ar.status = 'APPROVED' AND ar.kind = 'QUERY'));

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
       ar.statement_carries_protected_literal
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
       ar.statement_carries_protected_literal
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id
LEFT JOIN datasource d ON d.id = ar.datasource_id
WHERE ar.kind IN ('ROLE', 'RATE_RESET') AND ar.status = $1 ORDER BY ar.created_at DESC;

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

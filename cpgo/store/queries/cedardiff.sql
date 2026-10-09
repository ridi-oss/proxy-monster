-- name: CedarDiffPrincipals :many
SELECT principal FROM app_user UNION SELECT principal FROM principal_role
UNION SELECT principal FROM access_grant UNION SELECT principal FROM access_request;

-- name: CedarDiffRequests :many
SELECT ar.principal, ar.decided_by, d.name AS datasource_name, r.name AS role_name,
(SELECT qr.executed_by FROM query_result qr WHERE qr.task_id = ar.id ORDER BY qr.ordinal LIMIT 1) AS executed_by
FROM access_request ar LEFT JOIN app_role r ON r.id = ar.role_id LEFT JOIN datasource d ON d.id = ar.datasource_id;

-- name: CedarDiffGrants :many
SELECT ag.principal, ag.id, r.name FROM access_grant ag JOIN app_role r ON r.id = ag.role_id;

-- name: CedarDiffDatasources :many
SELECT id FROM datasource ORDER BY id;

-- name: CedarDiffPolicySources :many
SELECT cedar_src FROM policy;

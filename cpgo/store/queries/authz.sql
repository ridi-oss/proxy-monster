-- name: PolicyFingerprint :one
SELECT coalesce(md5(string_agg(id || '@' || updated_at, ',' ORDER BY id)), '')::text AS fingerprint
FROM policy WHERE enabled AND deleted_at IS NULL;

-- name: EnabledPolicies :many
SELECT id, cedar_src FROM policy WHERE enabled AND deleted_at IS NULL ORDER BY id;

-- name: PrincipalRoles :many
SELECT r.name FROM principal_role pr JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL
WHERE pr.principal = $1
UNION
SELECT r.name FROM access_grant ag JOIN app_role r ON r.id = ag.role_id AND r.deleted_at IS NULL
WHERE ag.principal = $1 AND ag.revoked_at IS NULL AND (ag.expires_at IS NULL OR ag.expires_at > now())
UNION
SELECT r.name FROM app_user u
JOIN group_member gm ON gm.user_id = u.id
JOIN app_group g ON g.id = gm.group_id AND g.deleted_at IS NULL
JOIN group_role gr ON gr.group_id = gm.group_id
JOIN app_role r ON r.id = gr.role_id AND r.deleted_at IS NULL
WHERE u.principal = $1 AND u.active;

-- name: IsDeactivated :one
SELECT EXISTS(SELECT 1 FROM app_user WHERE principal = $1 AND NOT active);

-- name: DatasourceNameTags :one
SELECT name, tags FROM datasource WHERE id = $1 AND deleted_at IS NULL;

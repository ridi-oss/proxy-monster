-- name: LiveRoleID :one
SELECT id FROM app_role WHERE name = $1 AND deleted_at IS NULL;

-- name: DeleteDirectRoles :exec
DELETE FROM principal_role WHERE principal = $1
AND role_id IN (SELECT id FROM app_role WHERE deleted_at IS NULL);

-- name: AddDirectRole :exec
INSERT INTO principal_role (principal, role_id) VALUES ($1, $2)
ON CONFLICT (principal, role_id) DO UPDATE SET principal = EXCLUDED.principal;

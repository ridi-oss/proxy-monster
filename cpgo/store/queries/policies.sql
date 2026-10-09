-- name: Roles :many
SELECT id, name, description FROM app_role WHERE deleted_at IS NULL ORDER BY name;

-- name: RoleAssignments :many
SELECT pr.id, pr.principal, pr.role_id, r.name AS role_name
FROM principal_role pr JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL WHERE true
ORDER BY pr.principal, r.name;

-- name: RoleAssignmentsOfPrincipal :many
SELECT pr.id, pr.principal, pr.role_id, r.name AS role_name
FROM principal_role pr JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL WHERE true AND pr.principal = $1
ORDER BY pr.principal, r.name;

-- name: RoleAssignmentsOfRole :many
SELECT pr.id, pr.principal, pr.role_id, r.name AS role_name
FROM principal_role pr JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL WHERE true AND pr.role_id = $1
ORDER BY pr.principal, r.name;

-- name: RoleAssignmentsOfPrincipalRole :many
SELECT pr.id, pr.principal, pr.role_id, r.name AS role_name
FROM principal_role pr JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL WHERE true AND pr.principal = $1 AND pr.role_id = $2
ORDER BY pr.principal, r.name;

-- name: MaskFns :many
SELECT id, name, kind FROM mask_fn WHERE deleted_at IS NULL ORDER BY name;

-- name: Policies :many
SELECT id, origin, system_key, name, cedar_src, enabled, updated_by, updated_at
FROM policy WHERE deleted_at IS NULL ORDER BY id;

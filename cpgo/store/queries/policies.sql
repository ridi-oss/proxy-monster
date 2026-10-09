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

-- name: Role :one
SELECT id, name, description FROM app_role WHERE id = $1 AND deleted_at IS NULL;

-- name: IsSystemRole :one
SELECT EXISTS(SELECT 1 FROM group_role gr JOIN app_group g ON g.id = gr.group_id
WHERE gr.role_id = $1 AND g.source = 'SYSTEM');

-- name: CreateRole :one
INSERT INTO app_role (name, description) VALUES ($1, $2) RETURNING id, name, description;

-- name: UpdateRole :exec
UPDATE app_role SET name = $1, description = $2 WHERE id = $3 AND deleted_at IS NULL;

-- name: DeleteRole :execrows
UPDATE app_role SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL;

-- name: RoleAssigned :one
SELECT EXISTS(SELECT 1 FROM principal_role WHERE principal = $1 AND role_id = $2);

-- name: AssignRole :one
INSERT INTO principal_role (principal, role_id) VALUES ($1, $2)
ON CONFLICT (principal, role_id) DO UPDATE SET principal = EXCLUDED.principal RETURNING id;

-- name: RoleAssignment :one
SELECT pr.id, pr.principal, pr.role_id, r.name AS role_name
FROM principal_role pr JOIN app_role r ON r.id = pr.role_id AND r.deleted_at IS NULL WHERE pr.id = $1;

-- name: UnassignRole :execrows
DELETE FROM principal_role WHERE id = $1;

-- name: MaskFn :one
SELECT id, name, kind FROM mask_fn WHERE id = $1 AND deleted_at IS NULL;

-- name: CreateMaskFn :one
INSERT INTO mask_fn (name, kind) VALUES ($1, $2) RETURNING id, name, kind;

-- name: UpdateMaskFn :exec
UPDATE mask_fn SET name = $1, kind = $2 WHERE id = $3 AND deleted_at IS NULL;

-- name: DeleteMaskFn :execrows
UPDATE mask_fn SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL;

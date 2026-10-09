-- name: GroupsOfUser :many
SELECT gm.user_id, g.id, g.name FROM group_member gm
JOIN app_group g ON g.id = gm.group_id AND g.deleted_at IS NULL WHERE gm.user_id = $1 ORDER BY g.name;

-- name: GroupsOfUsers :many
SELECT gm.user_id, g.id, g.name FROM group_member gm
JOIN app_group g ON g.id = gm.group_id AND g.deleted_at IS NULL ORDER BY g.name;

-- name: RoleRefsOfGroup :many
SELECT gr.group_id, r.id, r.name FROM group_role gr
JOIN app_role r ON r.id = gr.role_id AND r.deleted_at IS NULL WHERE gr.group_id = $1 ORDER BY r.name;

-- name: RoleRefsOfGroups :many
SELECT gr.group_id, r.id, r.name FROM group_role gr
JOIN app_role r ON r.id = gr.role_id AND r.deleted_at IS NULL ORDER BY r.name;

-- name: User :one
SELECT id, principal, display_name, email, source, external_id, active, created_at FROM app_user WHERE id = $1;

-- name: Users :many
SELECT id, principal, display_name, email, source, external_id, active, created_at FROM app_user ORDER BY principal;

-- name: GroupMemberCount :one
SELECT count(*) FROM group_member WHERE group_id = $1;

-- name: Group :one
SELECT id, name, description, source, external_id FROM app_group WHERE id = $1 AND deleted_at IS NULL;

-- name: GroupMemberCounts :many
SELECT group_id, count(*) FROM group_member GROUP BY group_id;

-- name: Groups :many
SELECT id, name, description, source, external_id FROM app_group WHERE deleted_at IS NULL ORDER BY name;

-- name: LockPrincipal :exec
SELECT pg_advisory_xact_lock(hashtext(sqlc.arg(principal)));

-- name: PrincipalOfUser :one
SELECT principal FROM app_user WHERE id = $1;

-- name: IsTombstone :one
SELECT EXISTS (SELECT 1 FROM app_user WHERE principal = $1 AND source = 'SCIM'
AND external_id IS NULL AND NOT active);

-- name: DeletePrincipalRoles :exec
DELETE FROM principal_role WHERE principal = $1;

-- name: DeleteTombstone :exec
DELETE FROM app_user WHERE principal = @principal AND source = 'SCIM' AND external_id IS NULL
AND NOT active AND (sqlc.narg(exclude)::bigint IS NULL OR id <> sqlc.narg(exclude));

-- name: DeactivateTokens :exec
UPDATE proxy_token SET revoked_at = now() WHERE principal = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: DeactivateGrants :exec
UPDATE access_grant SET revoked_at = now() WHERE principal = $1 AND revoked_at IS NULL;

-- name: DeactivateDaemonSessions :exec
UPDATE principal_session SET liveness_status = 'INACTIVE', absolute_expires_at = now()
WHERE principal = $1 AND kind = 'DAEMON' AND absolute_expires_at > now();

-- name: DeactivateWebSessions :execrows
UPDATE principal_session SET ended_at = now(), ended_reason = 'DEACTIVATED',
liveness_status = 'INACTIVE' WHERE principal = $1 AND kind = 'WEB' AND ended_at IS NULL;

-- name: DeleteEditorRequests :exec
DELETE FROM access_request WHERE creator_kind = 'EDITOR' AND principal = $1;

-- name: CreateUser :one
INSERT INTO app_user (principal, display_name, email, active) VALUES ($1, $2, $3, $4)
RETURNING id;

-- name: UpdateUser :exec
UPDATE app_user SET principal = $1, display_name = $2, email = $3, active = $4 WHERE id = $5;

-- name: TombstoneUser :exec
INSERT INTO app_user (principal, source, active) VALUES ($1, 'SCIM', FALSE)
ON CONFLICT (principal) DO UPDATE SET active = FALSE;

-- name: DeactivateUser :exec
UPDATE app_user SET active = FALSE WHERE id = $1;

-- name: CreateGroup :one
INSERT INTO app_group (name, description) VALUES ($1, $2) RETURNING id;

-- name: UpdateGroup :exec
UPDATE app_group SET name = $1, description = $2 WHERE id = $3 AND deleted_at IS NULL;

-- name: DeleteGroup :execrows
UPDATE app_group SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL;

-- name: GroupMembers :many
SELECT u.id, u.principal, u.display_name FROM group_member gm JOIN app_user u ON u.id = gm.user_id
WHERE gm.group_id = $1 ORDER BY u.principal;

-- name: RolesOfGroup :many
SELECT r.id, r.name FROM group_role gr JOIN app_role r ON r.id = gr.role_id AND r.deleted_at IS NULL
WHERE gr.group_id = $1 ORDER BY r.name;

-- name: AddGroupMember :execrows
INSERT INTO group_member (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;

-- name: RemoveGroupMember :execrows
DELETE FROM group_member WHERE group_id = $1 AND user_id = $2;

-- name: LockGroup :one
SELECT source, name FROM app_group WHERE id = $1 AND deleted_at IS NULL FOR UPDATE;

-- name: LiveRoleName :one
SELECT name FROM app_role WHERE id = $1 AND deleted_at IS NULL;

-- name: AddGroupRole :execrows
INSERT INTO group_role (group_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING;

-- name: RemoveGroupRole :execrows
DELETE FROM group_role WHERE group_id = $1 AND role_id = $2;

-- name: ProvisionUser :exec
INSERT INTO app_user (principal, email, source, active) VALUES ($1, $2, 'OIDC', TRUE)
ON CONFLICT (principal) DO UPDATE SET email = COALESCE(EXCLUDED.email, app_user.email), source = EXCLUDED.source
WHERE app_user.source <> 'SCIM';

-- name: UserIDByPrincipal :one
SELECT id FROM app_user WHERE principal = $1;

-- name: ProvisionGroup :one
INSERT INTO app_group (name, source) VALUES ($1, 'OIDC')
ON CONFLICT (name) WHERE deleted_at IS NULL DO UPDATE SET name = EXCLUDED.name RETURNING id;

-- name: GroupIDsOfUser :many
SELECT group_id FROM group_member WHERE user_id = $1;

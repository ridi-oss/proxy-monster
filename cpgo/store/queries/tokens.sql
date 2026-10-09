-- name: MintToken :one
INSERT INTO proxy_token (token_hash, kind, principal, roles, name, expires_at)
VALUES (sqlc.arg(token_hash), sqlc.arg(kind), sqlc.arg(principal), '[]'::jsonb, sqlc.arg(name), now() + (sqlc.arg(ttl)::bigint * interval '1 second')) RETURNING id, expires_at;

-- name: WireTokens :many
SELECT id, kind, principal, name, created_at, expires_at, revoked_at, last_used_at FROM proxy_token
WHERE principal = $1 AND kind IN ('SESSION', 'USER') ORDER BY created_at DESC;

-- name: WireToken :one
SELECT id, kind, principal, name, created_at, expires_at, revoked_at, last_used_at FROM proxy_token WHERE id = $1;

-- name: RevokeWireToken :execrows
UPDATE proxy_token SET revoked_at = now() WHERE id = $1 AND principal = $2 AND revoked_at IS NULL;

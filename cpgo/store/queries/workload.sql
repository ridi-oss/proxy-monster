-- name: MintWorkloadToken :one
INSERT INTO proxy_token (token_hash, kind, principal, roles, name, expires_at, claims)
VALUES (sqlc.arg(token_hash), 'WORKLOAD', sqlc.arg(principal), '[]'::jsonb, NULL, now() + (sqlc.arg(ttl)::bigint * interval '1 second'), sqlc.arg(claims)::jsonb)
RETURNING id, expires_at;

-- name: WorkloadBindings :many
SELECT id, name, description, issuer, subject, conditions, principal, purposes, mcp_scopes, ttl_seconds, enabled, created_at, updated_at
FROM workload_binding WHERE deleted_at IS NULL ORDER BY name;

-- name: WorkloadBinding :one
SELECT id, name, description, issuer, subject, conditions, principal, purposes, mcp_scopes, ttl_seconds, enabled, created_at, updated_at
FROM workload_binding WHERE id = $1 AND deleted_at IS NULL;

-- name: LockWorkloadBinding :one
SELECT id, name, description, issuer, subject, conditions, principal, purposes, mcp_scopes, ttl_seconds, enabled, created_at, updated_at
FROM workload_binding WHERE id = $1 AND enabled AND deleted_at IS NULL FOR SHARE;

-- name: IssuerWorkloadBindings :many
SELECT id, name, description, issuer, subject, conditions, principal, purposes, mcp_scopes, ttl_seconds, enabled, created_at, updated_at
FROM workload_binding WHERE issuer = $1 AND enabled AND deleted_at IS NULL ORDER BY id;

-- name: CreateWorkloadBinding :one
INSERT INTO workload_binding (name, description, issuer, subject, conditions, principal, purposes, mcp_scopes, ttl_seconds, enabled)
VALUES (sqlc.arg(name), sqlc.narg(description), sqlc.arg(issuer), sqlc.arg(subject), sqlc.arg(conditions)::jsonb, sqlc.arg(principal),
        sqlc.arg(purposes)::text[], sqlc.arg(mcp_scopes)::text[], sqlc.arg(ttl_seconds), sqlc.arg(enabled))
RETURNING id;

-- name: UpdateWorkloadBinding :execrows
UPDATE workload_binding SET description = sqlc.narg(description), issuer = sqlc.arg(issuer), subject = sqlc.arg(subject),
    conditions = sqlc.arg(conditions)::jsonb, principal = sqlc.arg(principal), purposes = sqlc.arg(purposes)::text[],
    mcp_scopes = sqlc.arg(mcp_scopes)::text[], ttl_seconds = sqlc.arg(ttl_seconds), enabled = sqlc.arg(enabled), updated_at = now()
WHERE id = sqlc.arg(id) AND deleted_at IS NULL;

-- name: DeleteWorkloadBinding :execrows
UPDATE workload_binding SET deleted_at = now(), enabled = false, updated_at = now() WHERE id = $1 AND deleted_at IS NULL;

-- name: RevokeWorkloadBindingTokens :execrows
UPDATE proxy_token SET revoked_at = now() WHERE workload_binding_id = $1 AND revoked_at IS NULL;

-- name: RevokeWorkloadBindingConsents :exec
UPDATE oauth_consent SET revoked_at = now(), updated_at = now() WHERE client_id = $1 AND revoked_at IS NULL;

-- name: PruneWorkloadTokenUse :exec
DELETE FROM workload_token_use WHERE expires_at <= now();

-- name: UseWorkloadToken :execrows
INSERT INTO workload_token_use (issuer, jti, expires_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING;

-- name: MintServiceToken :one
INSERT INTO proxy_token (token_hash, kind, principal, roles, name, expires_at, claims, workload_binding_id)
VALUES (sqlc.arg(token_hash), 'SERVICE', sqlc.arg(principal), '[]'::jsonb, sqlc.arg(name), sqlc.arg(expires_at), sqlc.arg(claims)::jsonb,
        sqlc.arg(workload_binding_id))
RETURNING id, expires_at;

-- name: MintWorkloadMcpToken :one
INSERT INTO proxy_token
(token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id, workload_binding_id)
VALUES (sqlc.arg(token_hash), 'MCP_ACCESS', sqlc.arg(principal), '[]'::jsonb, sqlc.arg(expires_at), sqlc.arg(resource), sqlc.arg(client_id),
        sqlc.arg(scope), sqlc.arg(refresh_family), sqlc.arg(consent_id), sqlc.arg(workload_binding_id))
RETURNING id;

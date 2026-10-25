-- name: DeleteStaleAuthorizationCodes :exec
DELETE FROM oauth_authorization_code WHERE expires_at <= now() OR used_at IS NOT NULL;

-- name: InsertAuthorizationCode :execrows
INSERT INTO oauth_authorization_code
(code_hash, client_id, principal, redirect_uri, resource, scope, code_challenge, expires_at, consent_id)
SELECT sqlc.arg(code_hash), sqlc.arg(client_id), sqlc.arg(principal), sqlc.arg(redirect_uri), sqlc.arg(resource),
       sqlc.arg(scope), sqlc.arg(code_challenge), now() + (sqlc.arg(ttl_seconds)::bigint * interval '1 second'), c.id
FROM oauth_consent c
WHERE c.id = sqlc.arg(consent_id) AND c.principal = sqlc.arg(principal) AND c.client_id = sqlc.arg(client_id)
  AND c.resource = sqlc.arg(resource) AND c.scope = sqlc.arg(scope) AND c.revoked_at IS NULL;

-- name: AuthorizationCodeForUpdate :one
SELECT id, principal, client_id, redirect_uri, resource, scope, code_challenge, consent_id,
       (used_at IS NULL AND expires_at > now())::boolean AS usable
FROM oauth_authorization_code WHERE code_hash = $1 FOR UPDATE;

-- name: UseAuthorizationCode :execrows
UPDATE oauth_authorization_code SET used_at = now() WHERE id = $1 AND used_at IS NULL;

-- name: ConsentActive :one
SELECT (revoked_at IS NULL)::boolean AS active FROM oauth_consent
WHERE id = $1 AND principal = $2 AND client_id = $3 AND resource = $4 AND scope = $5;

-- name: InsertMcpToken :exec
INSERT INTO proxy_token
(token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id, rotated_from)
VALUES (sqlc.arg(token_hash), sqlc.arg(kind), sqlc.arg(principal), '[]'::jsonb,
        now() + (sqlc.arg(ttl_seconds)::bigint * interval '1 second'), sqlc.arg(resource), sqlc.arg(client_id),
        sqlc.arg(scope), sqlc.arg(refresh_family), sqlc.arg(consent_id), sqlc.narg(rotated_from));

-- name: McpTokenForUpdate :one
SELECT id, kind, principal, coalesce(client_id, '') AS client_id, coalesce(resource, '') AS resource,
       coalesce(scope, '') AS scope, refresh_family, coalesce(consent_id, 0)::bigint AS consent_id,
       (revoked_at IS NOT NULL)::boolean AS revoked, expires_at <= now() AS expired, (rotated_at IS NOT NULL)::boolean AS rotated
FROM proxy_token WHERE token_hash = $1 FOR UPDATE;

-- name: RotateMcpRefreshToken :execrows
UPDATE proxy_token SET revoked_at = now(), rotated_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeTokenFamily :execrows
UPDATE proxy_token SET revoked_at = now()
WHERE refresh_family = $1 AND kind IN ('MCP_ACCESS', 'MCP_REFRESH') AND revoked_at IS NULL;

-- name: RevokeToken :execrows
UPDATE proxy_token SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL;

-- name: ActiveConsent :one
SELECT id FROM oauth_consent
WHERE principal = $1 AND client_id = $2 AND resource = $3 AND scope = $4 AND revoked_at IS NULL;

-- name: ListConsents :many
SELECT id, principal, client_id, resource, scope, created_at, updated_at
FROM oauth_consent WHERE principal = $1 AND revoked_at IS NULL ORDER BY updated_at DESC;

-- name: RevokeConsent :execrows
UPDATE oauth_consent SET revoked_at = now(), updated_at = now() WHERE id = $1 AND principal = $2 AND revoked_at IS NULL;

-- name: RevokeConsentTokens :exec
UPDATE proxy_token SET revoked_at = COALESCE(revoked_at, now())
WHERE consent_id = $1 AND kind IN ('MCP_ACCESS', 'MCP_REFRESH');

-- name: DaemonsByConsent :many
SELECT DISTINCT principal_session_id::bigint FROM proxy_token WHERE consent_id = $1 AND principal_session_id IS NOT NULL;

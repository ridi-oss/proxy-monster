-- name: DeviceLoginByUserCode :one
SELECT id, handle, user_code, ttl_seconds, status, principal, refresh_token_enc, expires_at,
coalesce(scopes, '') AS scopes, elevated_until FROM device_login WHERE user_code = $1;

-- name: DeviceLoginByHandle :one
SELECT id, handle, user_code, ttl_seconds, status, principal, refresh_token_enc, expires_at,
coalesce(scopes, '') AS scopes, elevated_until FROM device_login WHERE handle = $1;

-- name: CreateDeviceLogin :exec
INSERT INTO device_login (handle, user_code, interval_sec, ttl_seconds, expires_at, scopes)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: WebSessionRefreshToken :one
SELECT refresh_token_enc FROM principal_session
WHERE id = $1 AND kind = 'WEB' AND ended_at IS NULL
  AND absolute_expires_at > now() AND (idle_expires_at IS NULL OR idle_expires_at > now());

-- name: ApproveDeviceLogin :execrows
UPDATE device_login SET status = 'APPROVED', principal = $1, refresh_token_enc = $2, elevated_until = $3
WHERE handle = $4 AND status = 'PENDING' AND expires_at > now();

-- name: ConsumeDeviceLogin :execrows
UPDATE device_login SET status = 'CONSUMED' WHERE handle = $1 AND status = 'APPROVED' AND expires_at > now();

-- name: CreateDaemonSession :one
INSERT INTO principal_session
(principal, handle, refresh_token_enc, ttl_seconds, absolute_expires_at, liveness_status, renewal_token_hash, kind, scopes, elevated_until)
VALUES (sqlc.arg(principal), sqlc.arg(handle), sqlc.arg(refresh_token_enc), sqlc.arg(ttl_seconds), now() + make_interval(secs => sqlc.arg(window_seconds)), 'ACTIVE', sqlc.arg(renewal_token_hash), 'DAEMON', sqlc.arg(scopes), sqlc.arg(elevated_until))
RETURNING id, absolute_expires_at;

-- name: IssueSessionToken :one
INSERT INTO proxy_token (token_hash, kind, principal, roles, expires_at, principal_session_id)
VALUES (sqlc.arg(token_hash), 'SESSION', sqlc.arg(principal), '[]'::jsonb, now() + (sqlc.arg(ttl)::bigint * interval '1 second'), sqlc.arg(principal_session_id)) RETURNING id, expires_at;

-- name: DaemonSession :one
SELECT id, principal, ttl_seconds::bigint AS ttl_seconds, liveness_status, created_at, coalesce(scopes, '') AS scopes, elevated_until
FROM principal_session WHERE kind = 'DAEMON' AND id = $1;

-- name: DaemonSessionByRenewal :one
SELECT id, principal, ttl_seconds::bigint AS ttl_seconds, liveness_status, created_at, coalesce(scopes, '') AS scopes, elevated_until
FROM principal_session WHERE kind = 'DAEMON' AND renewal_token_hash = $1;

-- name: DaemonWithinWindow :one
SELECT absolute_expires_at > clock_timestamp() AS within FROM principal_session WHERE id = $1;

-- name: EndDaemonSession :one
UPDATE principal_session
SET ended_at = now(), ended_reason = 'SIGNED_OUT', liveness_status = 'INACTIVE', absolute_expires_at = LEAST(absolute_expires_at, now())
WHERE id = $1 AND kind = 'DAEMON' AND ended_at IS NULL
RETURNING principal;

-- name: RetireSessionTokens :exec
UPDATE proxy_token SET retired_at = now()
WHERE principal_session_id = $1 AND kind = 'SESSION' AND revoked_at IS NULL AND retired_at IS NULL;

-- name: RevokeDaemonTokens :many
UPDATE proxy_token SET revoked_at = now()
WHERE principal_session_id = sqlc.arg(principal_session_id) AND revoked_at IS NULL AND (kind <> 'SESSION' OR NOT sqlc.arg(replaced)::boolean)
RETURNING consent_id;

-- name: RevokeOrphanConsents :exec
UPDATE oauth_consent c SET revoked_at = now(), updated_at = now()
WHERE c.id = ANY(sqlc.arg(ids)::bigint[]) AND c.revoked_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM proxy_token t WHERE t.consent_id = c.id AND t.revoked_at IS NULL AND t.expires_at > now());

-- name: PmonConsent :one
INSERT INTO oauth_consent (principal, client_id, resource, scope) VALUES ($1, $2, $3, $4)
ON CONFLICT (principal, client_id, resource, scope) WHERE revoked_at IS NULL DO UPDATE SET updated_at = now()
RETURNING id;

-- name: MintMcpAccessToken :one
INSERT INTO proxy_token
(token_hash, kind, principal, roles, expires_at, resource, client_id, scope, refresh_family, consent_id, principal_session_id)
VALUES ($1, 'MCP_ACCESS', $2, '[]'::jsonb, $3, $4, $5, $6, $7, $8, $9) RETURNING id;
